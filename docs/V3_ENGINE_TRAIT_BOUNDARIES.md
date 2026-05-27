# V3 Engine Trait Boundaries (Stage 1)

**Status.** Round 5 (acceptance round) was the final design-review
round. PR
[#20](https://github.com/Shekyl-Foundation/shekyl-core/pull/20)
absorbed the linear-append review commits per round (Rounds 1, 2,
3, 4a, 4b, 5 — at the upper bound of the 4–6 review-rounds rule
per
[`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc))
and merged to `dev` on 2026-05-01 (merge commit `40093ac7a`). The
Round 5 pre-drafting gap-check confirmed Case A (spec is
structurally complete; Round 6 unnecessary unless post-draft
review surfaces unexpected items). **Stage 1 PR 1
([PR #21](https://github.com/Shekyl-Foundation/shekyl-core/pull/21),
`DaemonEngine` extraction) landed the first per-trait migration
against this spec on 2026-05-02.** **Stage 1 PR 2
(`LedgerEngine` extraction) landed the second per-trait migration
against this spec on 2026-05-04**, with three pre-flight doc-only
spec amendments threaded through the lifecycle: Phase 0
([PR #22](https://github.com/Shekyl-Foundation/shekyl-core/pull/22),
reservation-tracker ownership correction), Phase 0b
([PR #23](https://github.com/Shekyl-Foundation/shekyl-core/pull/23),
trait surface narrowing), and Phase 0c
([PR #25](https://github.com/Shekyl-Foundation/shekyl-core/pull/25),
drop `transfers()` for `!Clone` discipline). The
[Stage 1 PR 2 design doc](design/STAGE_1_PR_2_LEDGER_ENGINE.md)
§2.2 captures the lifecycle-not-just-pre-flight discipline pattern
that this drift count surfaced. Subsequent per-trait PRs follow
§8.1's within-stage-1 ordering and §8.2's amendment co-landing
rule.

- **Round 1 record:** `d387bff1d` (initial draft on this branch);
  content originally landed on `dev` outside the review-round
  workflow as `c0a3b75ec` and was reverted by `3ed7ff2c7` to put the
  spec on the markdown-only PR-review path required by
  [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc).
- **Round 2 record:** `7bd91f402` (substantive revisions: §1.4
  actor-shape discipline, §2.3 `RefreshEngine` collapse to
  producer/driver, §2.5 two-trait `DaemonEngine`, §3.2 async-cascade
  framing, §6.2 deterministic RNG injection).
- **Round 3 record:** `3e38b26cf` — structural gap closures (§2.8
  lifecycle, §3.3 concurrency, §3.4 cancellation, §2 `&mut self →
  &self` sweep, §5.1 `RuntimeFailure`, §4 idempotency column) plus
  the in-round `EconomicsEngine` augmentation (seven traits).
- **Round 4a record:** `d103d8447` — design closure across 20
  items in four phases (Phase 1 / Phase 2a / Phase 2c / Phase 2b);
  see Round 4a description below.
- **Round 4b Phase 1 record:** `143b965bc` — mechanical fill-in
  carry-forwards (11 items): §1.2 seven-traits-Stage-1-only pin,
  §1.5 `StakeEngine` positive example, new §1.6 documentation
  discipline, §3.5 long-running observability, §4 cancel-class
  column, §4.2 `#[tokio::test]` clarification, §6.1
  mocks-vs-contract bullet, new §8.2 amendment co-landing rule,
  §10.0 separator strengthening, new `docs/PERFORMANCE_BASELINE.md`,
  `FOLLOWUPS.md` baseline + cutover entries.
- **Round 4b Phase 2 record:** `0d8ff9ef0` — seven gap-check
  additions + two cross-reference closures + one polish: §1.4
  `Send`-on-parameters; §1.6↔§5.2 cross-reference; §3.3.1
  baseline definition; new §3.4.4 long-running cancellation
  pattern with §3.4.4→§3.4.5 renumber; §5.1 supervisor restart
  budget; new §5.2 caller retry contract with PendingTx/Daemon
  layered-call pinning; new §6.3 hybrid construction discipline;
  §8.2 PR-description bullet elevation; §10.1.3 verification
  gates + orthogonal-properties exclusion.
- **Round 5 record:** the commit landing this state on the chore
  branch; commit message captures nine operational-tightening
  items plus the panic-strategy enumeration extension surfaced
  by the Round 5 pre-drafting gap-check.

**Planned trajectory.** Round 4 is split into 4a and 4b; 4b is
further split into Phase 1 (carry-forwards) and Phase 2
(gap-check additions).

- **Round 4a — design closure (20 items).**
  Phase 1 (4 foundational pins): lifecycle async resolution,
  `EconomicsError` pinning, `EconomicsParametersSnapshot`
  Resolution C, `EngineConfig` pinning. Phase 2a (9 in-place
  refinements): §2.7 trio (discipline-test (d) clause,
  prescriptive `parameters_snapshot` docstring,
  consensus-as-truth pin), §2.8.2 drop-order softening,
  per-trait `RuntimeFailure` enumeration, §5.1 draining-ordering
  clarity, §2.8.4 timeout configurability surface, §2 preamble
  `pub(crate)` visibility, §3.3.4 unsafe-pattern revisit.
  Phase 2c (7 design-closure additions): §3.3 interior-mutability
  measurement gate, §1.5 criteria for trait identity (with
  scope-guard meta-pattern), §5.1 `RuntimeFailure` ×
  cancellation composition, §2.7 consumer-driven justification
  rule, §3.5 observability-via-tracing rejection, §2.7
  `EconomicsEngine` scope guard, §2.7 `DESIGN_CONCEPTS.md`
  cross-reference. Phase 2b (1 synthesis): §10 deferred
  subsection.
- **Round 4b — mechanical fill-in + operational refinement
  (18 items, current round).** Phase 1 (11 carry-forwards;
  committed at `143b965bc`): see Phase 1 record above. Phase 2
  (7 gap-check additions; this commit): §1.4 `Send`-on-parameters
  discipline, §3.3.1 baseline definition tightening, new §3.4.4
  long-running cancellation pattern (renumbers existing
  dispositions to §3.4.5), §5.1 supervisor restart-budget
  acknowledgement, new §5.2 caller retry contract (with
  layered-call PendingTx/Daemon pinning), new §6.3 hybrid
  construction discipline, §10.1.3 verification gates +
  orthogonal-properties exclusion. Plus two cross-reference
  closures from Phase 1 (§1.6→§5.2; §3.5↔§3.4.4) and one polish
  (§8.2 PR-description third bullet).
- **Round 5 — operational tightening + acceptance (current
  round; 9 items + panic-strategy enumeration extension).**
  Items: §3.3.1 re-baseline frozen-numbers / per-PR-deltas /
  Stage-1-close policy; §3.4.4 progress-channel backpressure
  with §10.4.3 consistency; §5.2 layered-call error preservation
  (verbatim-not-wrapping) + three-case walk table-form polish;
  §6.2 master-seed-derivation contract for hybrid tests; §8.2
  two "Why" paragraphs consolidation; §10.1.3 fifth bullet
  (deployment-context properties incl. panic strategy) +
  resource-consumption cross-reference to §10.2.2; new §10.6.4
  deployment-configuration pinning re-litigation (4 enumeration
  items: allocator, TLS, tokio runtime config, panic strategy);
  §1.5 enumeration update (sixth scope guard, back-filled from
  §10.6.4). Round 5 pre-drafting gap-check ran against three
  framings ("implicit but discoverable late" in unaddressed
  domains; "what would Stage 2's first PR reviewer ask?"; "what
  would Phase 2b's `StakeEngine` spec author cite?") and yielded
  one strong candidate (panic strategy) absorbed via §10.1.3 +
  §10.6.4 enumeration extensions. Case A confirmed.

**Round-discipline meta-pattern (named in Round 4a).** Each
round so far has introduced one or more *over-comfortable
claims* — load-bearing premises articulated under-strongly that
read as comforting on first review and require correction in the
next round. Round 3 had three such claims (§7's invariant scope,
§2.7's `Result` ceremony, §3.3.6's snapshot leak), all caught in
Round 4a. The "what are we missing" check between rounds is
framed as *"what did writing the previous round surface that we
didn't anticipate?"* rather than *"what general gaps remain?"* —
the first framing catches drafting-induced discoveries; the
second misses them. Round 4a's drafting discipline applies the
lens internally: when a section's claim depends on a load-bearing
premise, articulate the premise explicitly rather than leaving it
implicit.

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

**Seven traits is the V3.0 trait surface; subsequent expansion is
additive (Round 4b — Item 4).** The Stage 1 surface stabilizes at
exactly seven traits (`KeyEngine`, `LedgerEngine`, `RefreshEngine`,
`PendingTxEngine`, `DaemonEngine`, `PersistenceEngine`,
`EconomicsEngine`). Phase 2b's `StakeEngine` (per §10.5.1) and
V3.x's `ArchivalEngine` (and any anonymity-network-coordination
trait per §10.4.4) are *additive* — they extend the trait set
without restructuring the seven traits or their surfaces. Any
proposed change to the seven traits' shape (rather than additions
alongside them) is structural revision and re-opens this spec for
a new round per §7's invariants. The §1.5 trait-identity criteria
govern additive proposals; the §7 invariants govern structural
preservation. The two are complementary disciplines.

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
| Generic `DaemonClient` *implementation* | Stage 1 PR 1 landed the `Engine<S, D: DaemonEngine = DaemonClient>` parameterization (per §2.5; `MockDaemon`-driven `start_refresh` coverage now exists end-to-end via `Engine::replace_daemon`). V3.2 generalizes the production constructors (`Engine::create`, `Engine::open_full`) over `D` alongside the `DaemonEngine`-to-`pub` promotion, retiring the `#[cfg(test)] pub(crate) replace_daemon` helper. |
| Generic `LocalLedger` *implementation* | Stage 1 PR 2 landed the `Engine<S, D = DaemonClient, L: LedgerEngine = LocalLedger>` parameterization (per §2.2 post-Phase-0c surface). PR 4 C6β retired the original `MockLedger` parallel-implementation in favour of the no-Mock substrate `FaultInjecting<LocalLedger>::new(LocalLedger::from_test_blocks(Vec::new()))`; `apply_scan_result` retry coverage now exists end-to-end via `Engine::replace_ledger` wrapping the production `LocalLedger` with the trait-level failure-injection wrapper (per `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X C6β + §6.1 "no-Mock substrate inheritance discipline"). The `pub(crate) trait LedgerEngine` declares four methods (`synced_height`, `snapshot`, `balance`, `apply_scan_result`); `Engine::start_refresh` and the producer task `run_refresh_task` are generalized over `L`. The synchronous wrappers `Engine::refresh` / `Engine::refresh_with` remain `LocalLedger`-specialized because the trait's `apply_scan_result` is `async fn` and the sync entry points cannot dispatch through it without a runtime-handle threading story (queued at V3.x in `FOLLOWUPS.md`). V3.2 generalizes the production constructors (`Engine::create`, `Engine::open_full`) over `L` alongside the `LedgerEngine`-to-`pub` promotion, retiring the `#[cfg(test)] pub(crate) replace_ledger` helper. The `LocalLedger` aggregate landed as `pub` (not `pub(crate)`) because Rust requires every default type parameter on a `pub` type to be at least as visible as the type itself; the trait `LedgerEngine` itself stays `pub(crate)` per §1.4. |

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

**Parameter discipline (Round 4b — Item 18).** Trait method
parameters that the Stage 4 actor receives across the mailbox
boundary must also be `Send + 'static`. Stage 1's concrete
in-process structs accept any parameter shape — there is no
mailbox to cross — but Stage 4's actor mailbox is a typed
message channel: a parameter that isn't `Send + 'static` cannot
cross the boundary. The discipline is therefore "shape Stage 1
parameters as if they had to satisfy the Stage 4 mailbox today."
The alternative (discovering non-`Send` parameters at Stage 4
cutover) forces signature changes that §7's invariants forbid;
the time to enforce the property is at trait declaration, not
at cutover. Concrete implications: parameters cannot hold
`&dyn Trait` borrows whose underlying data is non-`Send`; cannot
hold `MutexGuard<'_, T>` (lock guards aren't `Send` across most
lock types); cannot hold raw pointers (`*const T` / `*mut T`);
cannot hold `Rc<T>` (use `Arc<T>` instead). Owned values,
`Arc<T>` where `T: Send + Sync`, `&T: Sync + 'static` (e.g.,
`&'static str`, references to data behind `Arc`), and trait
references constrained `Clone + Send + Sync + 'static` (per the
existing §2.5 `DaemonEngine` pattern) all clear the discipline.
Applying the test to §2: every trait method's parameter list
satisfies this property today — `Amount`, `SubaddressIndex`,
`LedgerSnapshot`, `Reservation`, `TransactionSubmission` are all
owned `Send + 'static`; the `&D: DaemonEngine` parameter on
`RefreshEngine::produce_scan_result` clears the discipline
because §2.5 pins `DaemonEngine: Clone + Send + Sync + 'static`,
making the borrow Stage-4-equivalent to a cloned actor handle.
The discipline is "implicit but discoverable late" — Stage 1
compilation succeeds without it; Stage 4 compilation fails after
the trait surface is committed. Pinning at Stage 1 declaration
prevents the late discovery.

Stage 4 makes the discipline operational: an `&self` trait method
against a `kameo` actor is a `tell`/`ask`-shaped message
round-trip; an `&mut OtherTrait` parameter has no Stage-4
equivalent; a parameter that isn't `Send + 'static` cannot enter
the mailbox; a return that borrows internal state has no Stage-4
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

### 1.5 Criteria for trait identity (Round 4a — Item 15)

§1.4 names the discipline that governs *method shape*. §1.5
names the discipline that governs *trait existence* — what
makes something a trait vs an inherent method on `Engine<S>`
vs a free function in a module. Without this discipline, a
future contributor proposing an 8th trait (or proposing to
merge two existing ones) has no spec-articulated criterion to
evaluate against; reviewers fall back on aesthetic judgment
rather than load-bearing criteria.

A trait exists iff it satisfies all three of:

1. **Distinct state ownership at Stage 4** — the trait owns
   state that becomes one actor's mailbox-private state at
   Stage 4. Two traits sharing the same Stage 4 actor's state
   collapse to one trait; a "trait" whose state lives on
   another trait's actor is not a trait, it's a method on the
   actual owner.
2. **Distinct failure-isolation domain** — the trait can fail
   independently under Stage 4's supervisor strategy without
   taking down the rest of the engine. A trait whose failure
   semantics are inseparable from another trait's (e.g., its
   crash means the engine is dead anyway) doesn't earn its own
   supervisor strategy and therefore doesn't earn its own
   trait.
3. **Either** *(a)* **a cross-cutting concern that multiple
   consumers need** — the trait is consumed by two or more
   other traits or `Engine<S>`-level operations, and
   re-implementing the cross-cutting derivation per consumer
   invites the scattered-derivation bug class — **or**
   *(b)* **an isolatable subsystem with explicit lifecycle** —
   the trait has a single consumer (typically `Engine<S>`'s
   orchestration) but its work is naturally separated by its
   own lifecycle (start, pause/resume, cancel, close) such that
   bundling it into the consumer would conflate two different
   concurrency stories.

The OR clause in (3) reflects that two distinct shapes drive
trait existence: cross-cutting reuse (clause 3a) and
isolatable lifecycle (clause 3b). Both are load-bearing; either
alone, combined with (1) and (2), justifies trait status.

**Applied to the seven traits.**

| Trait | (1) Distinct state at Stage 4 | (2) Failure isolation | (3) Justification |
|---|---|---|---|
| `KeyEngine` | yes — `AllKeysBlob` and KEK material | yes — key actor crash is recoverable; supervisor restarts and re-derives via passphrase | 3a — cross-cutting (consumed by `RefreshEngine` for output-decoding, `PendingTxEngine` for signing, `Engine<S>` for address rendering) |
| `LedgerEngine` | yes — `LedgerState`, `LedgerSnapshot` | yes — ledger actor crash is recoverable from persistence | 3a — cross-cutting (consumed by `RefreshEngine` for tip checks, `PendingTxEngine` for output selection, `Engine<S>` for balance; per-transaction history is read directly from the underlying `LedgerBlock` rather than through the trait — see §2.2's 2026-05-03 transfer-clone discipline amendment) |
| `RefreshEngine` | yes — producer-side scan-cursor state | yes — refresh actor crash is recoverable; supervisor restarts and re-issues from current ledger tip | 3b — isolatable subsystem (single consumer `Engine<S>`; explicit lifecycle: start, pause via cancellation token, resume on next call, close) |
| `EconomicsEngine` | yes — at V3.x, adaptive-burn observation state; at V3.0, no state but the surface is fixed | yes — economics actor crash at V3.x surfaces `RuntimeFailure`; consumers continue with last-good snapshot | 3a — cross-cutting (consumed by `Engine<S>` for fee computation, `PendingTxEngine` for burn-fraction inputs, V3.x's `StakeEngine` and `ArchivalEngine` for parameter queries) |
| `DaemonEngine` | yes — connection state, request queue | yes — daemon actor crash is recoverable; supervisor restarts and re-establishes connection | 3a — cross-cutting (consumed by `RefreshEngine` for chain queries, `PendingTxEngine` for fee estimates and submit, `Engine<S>` for direct RPC calls) |
| `PersistenceEngine` | yes — `WalletFile` handle, advisory lock, IO buffers | yes — persistence actor crash signals "wallet may be in inconsistent on-disk state"; supervisor strategy is non-recoverable for this trait specifically | 3b — isolatable subsystem (single *runtime* consumer `Engine<S>`; spawn-time consumer for `LedgerEngine` and `KeyEngine` hydration is a lifecycle dependency on the §2.8.1 spawn-graph, not a runtime consumption on the call-graph; explicit lifecycle: open, save, rotate-password, close-with-flush) |
| `PendingTxEngine` | yes — reservation tracker, in-flight txn state | yes — pending-tx actor crash is recoverable; supervisor restarts; in-flight reservations are cleared per restart-and-fail-pending semantics | 3b — isolatable subsystem (single consumer `Engine<S>`; explicit lifecycle: build, submit, discard, status-query) |

**Hypothetical 8th-trait evaluation.** Two negative examples
demonstrate the criteria mechanically:

- **`MiningEngine`** (proposed for in-wallet mining-pool
  monitoring). Fails (1) — no Stage 4 state distinct from
  `DaemonEngine`'s pool RPC connection. Fails (3) — no
  cross-cutting consumers (mining is a single-consumer concern
  for the mining UI surface) and no isolatable lifecycle
  (operations are RPC fan-out via `DaemonEngine`). Correct
  shape: methods on `DaemonEngine` or inherent on `Engine<S>`.
- **`SubaddressEngine`** (proposed for subaddress-management
  workflows). Fails (1) — subaddress data lives in
  `PersistenceEngine` via `WalletPrefs` and is derived via
  `KeyEngine`. Fails (2) — no independent failure domain;
  subaddress operations fail when key or persistence fails.
  Correct shape: methods on `KeyEngine` (derivation) and
  `PersistenceEngine` (persistence of named-subaddress
  metadata).

Both negative examples illustrate clause (1) as the strictest
gate: trait proposals that don't own distinct Stage 4 actor
state are not traits, regardless of how cohesive the
"subsystem" feels conceptually.

A positive example demonstrates the criteria validating an
additive proposal:

- **`StakeEngine`** (Phase 2b additive trait per §10.5.1).
  Clears (1) — owns per-stake records, the stake FSM state,
  and the principal-pool aggregation state at Stage 4; this
  state is distinct from `LedgerEngine`'s ledger state and
  from `EconomicsEngine`'s parameter-derivation state.
  Clears (2) — independent failure-isolation domain. A stake
  actor crash is recoverable by re-hydrating from chain
  state (the principal pool is consensus-derived; per-stake
  records reconstruct from chain history); a permanent
  stake failure surfaces `RuntimeFailure` to claim/unstake
  callers without taking down `LedgerEngine` or
  `EconomicsEngine`. Clears (3a) — cross-cutting concern
  with named consumers: `Engine<S>` for stake-aware
  operations (registering a stake, claiming yield),
  V3.x's `ArchivalEngine` for sibling-actor queries via
  `is_active_staker(entity_id)`, and external observers via
  JSON-RPC at V3.2+. Trait status validated; Phase 2b
  design proceeds against the §1.5 framework.

The positive example confirms the criteria don't only reject
inappropriate proposals — they also validate appropriate
ones, providing a structural framework for Phase 2b's
design phase to operate against.

**Scope-guard meta-pattern.** The spec uses *scope guards* —
explicit "no, here's why" rejections with named reasoning — to
prevent recurring pull-outside-scope patterns:

- **Consensus-as-truth** (in §2.7) rejects wallet-side
  enforcement of consensus rules.
- **Observability-via-tracing** (in §3) rejects trait-level
  observability hooks.
- **Economic-rationale-in-DESIGN_CONCEPTS** (in §2.7's
  cross-references) rejects the trait spec as the catalog of
  industry economic failures.
- **Lifecycle-as-inherent** (in §2.8.7) rejects lifecycle
  methods as trait methods.
- **Consumer-driven justification** (in §2.7's discipline
  test) rejects speculative method additions to
  `EconomicsEngine`.
- **Deployment-configuration-as-binary-concern (Round 5 —
  Item 9; in §10.1.3 fifth bullet and §10.6.4)** rejects
  spec-level pinning of allocator, TLS, tokio runtime config,
  and panic strategy. Three are spec-indifferent; the fourth
  (panic strategy) is spec-dependent — §5.1 assumes
  `panic=unwind` — but the *enforcement* of the configuration
  is a deployment concern, not a trait-surface concern. The
  scope guard prevents the recurring proposal pattern of
  "should the spec pin allocator X / TLS Y / runtime config
  Z?"; the answer is "no, those are deployment-context
  properties; revisit only if a property's choice has trait-
  surface consequences not yet captured here" (per §10.6.4's
  threshold).

Scope guards are the spec's most durable structural feature.
Silent omission ("the spec doesn't mention X") invites future
contributors to propose X; explicit rejection with named
reasoning closes the question. New trait proposals or method
additions that would violate a scope guard require *explicit
revisit of the guard*, not silent extension; the revisit
either updates the guard with new rationale or rejects the
proposal. The same discipline applies to (1)/(2)/(3) above:
proposals that fail any clause are rejected as "not a trait,"
not folded into the existing trait set without examination.

### 1.6 Documentation discipline (Round 4b — Item 6)

§1.4 governs method *shape*; §1.5 governs trait *existence*;
§1.6 governs method *documentation*. Three rustdoc disciplines
apply to every trait method in §2:

1. **Panic conditions are documented.** Any trait method that
   *can* panic — including via debug assertion, via integer
   overflow under `debug_assertions`, via `expect`/`unwrap` on
   internal invariants, or via explicit `panic!` — must
   document the panic condition in a `# Panics` rustdoc
   section. Methods that cannot panic under any input
   (genuinely panic-free) say so in a brief "Never panics"
   note where the absence of a `# Panics` section would
   otherwise be ambiguous. Stage 4 actor-backed
   implementations carry the same discipline: an actor's
   message handler that panics surfaces as
   `RuntimeFailure { reason: ActorCrashReason::Panic, … }`
   per §5.1, and the *trait method's* rustdoc must name the
   panic condition that produces this `RuntimeFailure`.
2. **Cancellation behavior is documented.** Per §3.4.3, every
   async trait method belongs to one of three cancellation
   classes (a / b / c). The method's rustdoc names its class
   explicitly. Round 4b's per-method classification (Item 1)
   in §4's async-story table is the canonical mapping;
   rustdoc text references the table rather than re-stating
   the classification per method.
3. **Idempotency is documented.** Per §4's idempotency
   column, methods marked "yes," "conditionally," or "no"
   carry the explanation as a one-line rustdoc note. The
   "conditionally" case names the explicit condition (e.g.,
   "idempotent given the same `ScanResult` against the same
   starting `synced_height`"). The §4 classification is the
   *property* the method offers; §5.2 is the *operational
   retry contract* callers derive from it (when to retry, when
   not to retry, how the layered-call relationships compose).
   Method rustdoc names the §4 classification; callers consult
   §5.2 for the retry behavior to adopt.

The disciplines are documentation-as-contract: a method's
rustdoc names what callers can rely on. Stage 4 cutover does
not change rustdoc — the documented contract persists across
the implementation swap. Round 4b's mechanical fill-in
applies these disciplines per-method as the per-method
classifications land in §4 (Item 1).

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

**Visibility (Round 4a — Item 13 pin).** The seven traits ship
**`pub(crate)` until JSON-RPC server cutover** (V3.2 per
`docs/FOLLOWUPS.md`'s `wallet_rpc_server` Rust migration
target). The traits are internal contracts of `shekyl-engine-core`
that consumers (the wallet binaries, the `shekyl-engine-rpc`
JSON-RPC server) reach via `Engine<S>`'s inherent methods, not
via direct trait dispatch. `pub(crate)` keeps the trait surfaces
*internally* reviewable while the implementations stabilize and
the JSON-RPC contract solidifies; promoting to `pub` happens
when a downstream consumer — the JSON-RPC server, an embedding
library, or a non-CLI binary — needs to dispatch through trait
references rather than `Engine<S>` calls.

This visibility decision shapes the test boundary (§6). With
`pub(crate)` traits, integration tests against fully-mocked
engines must live *in-crate* at
`rust/shekyl-engine-core/tests/` or use `#[cfg(test)] pub(crate)`
re-exports; tests in a separate crate cannot import the trait
or its `Mock*` implementors. §6 follows this: the `Mock*`
implementors are `#[cfg(test)] pub(crate)` in
`engine::test_support`, and the integration tests that drive a
fully-mocked `Engine<SoloSigner, MockKey, …>` live in-crate.

Promoting traits to `pub` later is *additive* and does not
require trait-surface changes — only visibility relaxation. The
Round 4a pin is "`pub(crate)` for V3.0; revisable to `pub` at
V3.2 alongside `wallet_rpc_server` Rust migration"; future
rounds adjust visibility, not surface.

The `Mock*` implementors are `pub(crate)` for the same reason:
they're test-only support, not consumer-facing types.

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

**Stage 1 surface (post-M3 migration; source of truth at
[`rust/shekyl-engine-core/src/engine/traits/key.rs:616`](../rust/shekyl-engine-core/src/engine/traits/key.rs#L616)).**

```rust
pub(crate) trait KeyEngine: Send + Sync + 'static {
    type Error: Into<KeyEngineError>;

    /// Account-level public address material. Cheap; does not
    /// touch secrets. Stable for the wallet's lifetime — the
    /// only trait method returning a borrowed reference rather
    /// than an owned message, because address material is not
    /// bound to any per-call context.
    fn account_public_address(&self) -> &AccountPublicAddress;

    /// Derive a subaddress for a specific purpose
    /// (`SubaddressPurpose::Recipient` returns
    /// `SubaddressFor::Recipient(RecipientSubaddress { encoded,
    /// kem_pk })`; `SubaddressPurpose::Audit` returns
    /// `SubaddressFor::Audit(SubaddressKeyPair { spend_pk, view_pk })`).
    /// Deterministic in `(view_secret, subaddress_index, purpose)`.
    fn derive_subaddress(
        &self,
        idx: SubaddressIndex,
        purpose: SubaddressPurpose,
    ) -> Result<SubaddressFor, Self::Error>;

    /// Workflow: try to claim an on-chain output for this wallet.
    /// Bundles X25519 view-tag pre-filter + hybrid decap + HKDF
    /// chain + key-image computation + handle-table insertion
    /// behind a single trait boundary. Returns
    /// `OutputClaimResult::Mine(OutputClaim { handle, key_image,
    /// amount_atomic_units })` on detection or
    /// `OutputClaimResult::NotMine` on rejection. **No secret
    /// material crosses the trait boundary** — the orchestrator
    /// receives only an opaque `OutputHandle` plus non-secret
    /// on-chain metadata.
    fn try_claim_output(
        &self,
        input: &OutputDetectionInput,
    ) -> impl std::future::Future<Output = Result<OutputClaimResult, Self::Error>> + Send;

    /// Workflow: sign a fully-prepared transaction. Each
    /// `TxInputSigningContext` references its per-output spending
    /// capability via `handle: OutputHandle` (returned by an
    /// earlier `try_claim_output` call); the implementor resolves
    /// the handle internally to recover the per-output spending
    /// material needed to produce the per-input signature.
    fn sign_transaction(
        &self,
        tx: &TxToSign,
    ) -> impl std::future::Future<Output = Result<TxSignatures, Self::Error>> + Send;
}
```

**Round 2 dispositions (post-M3 reframing).** The original
Round-2 dispositions targeted the pre-migration primitive-shape
trait (`sign_with_spend`, `view_ecdh`, `ml_kem_decapsulate`,
`derive_subaddress_public`); Stage 1 PR 3's Round 2 substantive
workflow-shape pivot (commits `1c20fb7ee`, `3e3cb292c` —
see [`STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
"Round trajectory") replaced those primitives with the
workflow-shape methods above (`try_claim_output`,
`sign_transaction`), and Round 3 added the handle-indirected
contract that ensures no secret material crosses the trait
boundary. The pre-migration Q9.1/Q9.2/Q9.3 dispositions are
preserved here for the design-trajectory record; their
post-M3 analogues live in
[`STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
§7.14 (Pattern-6 replay/idempotency contract) and the
source-trait docstrings.

- **Q9.1 (signing async-ness): closed.** `sign_with_spend`,
  `view_ecdh`, `ml_kem_decapsulate` were `async fn` in the
  pre-migration surface. **Post-M3 analogue:** the workflow-shape
  methods `try_claim_output` and `sign_transaction` are
  RPIT-`Future` returning (compatible with `async fn` in trait
  but written explicitly to bound the future with `Send`);
  pure-derivation methods (`account_public_address`,
  `derive_subaddress`) stay sync.
- **Q9.2 (`SignDomain` enumeration): closed `#[non_exhaustive]`.**
  V3.0 enumerated four domains (output-secret derivation,
  transaction signature, FCMP++ witness, ml-kem challenge);
  Stage 4 adds multisig witness / partial signature variants
  additively without re-opening the trait. **Post-M3 placement:**
  `SignDomain` is no longer a trait-level concept; per the
  workflow-shape pivot, HKDF domain separation lives inside
  `LocalKeys` via the `SignsInDomain` marker trait + per-domain
  markers (see [`STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
  §3.1.4 / Sub-bundle A).
- **Q9.3 (explicit `wipe()` method): closed no.** `AllKeysBlob:
  ZeroizeOnDrop`; the Stage 4 actor's `Drop` inherits the wipe.
  The trait contract is "the implementor zeroizes on drop and on
  process-explicit lock"; no method is needed. **Post-M3 status:**
  unchanged. The `AllKeysBlob` `ZeroizeOnDrop` migration landed
  via `chore/allkeysblob-zeroize-realignment` (post-M3a,
  Phase 0e closure per [`STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
  §5.1).

### 2.2 `LedgerEngine`

**Ownership.** `WalletLedger` (the persistent ledger),
`LedgerIndexes` (the runtime-only derived indexes rebuilt at every
open per the *RuntimeWalletState audit* decision-log entry,
2026-04-25). The reservation tracker is owned by `PendingTxEngine`;
see §2.4.

Reservations are claims on ledger outputs, so the conceptual
coupling is structural: `PendingTxEngine`'s build path reads the
underlying `LedgerBlock` state that `LedgerEngine` owns —
specifically `LedgerBlock::height`, `LedgerBlock::block_hash_at`,
and `LedgerBlock::spendable_outputs` — not the
`LedgerEngine::balance` or `LedgerEngine::snapshot` trait methods.
See `rust/shekyl-engine-core/src/engine/pending.rs`'s
`build_pending_tx_in_state` for the actual build-path call sites,
and §2.2's 2026-05-03 transfer-clone discipline amendment for
why no trait-level transfer-enumeration method exists at Stage 1.
On `dev` today the access path is `Engine::ledger()` (which
returns `&WalletLedger`) followed by descent into the nested
`WalletLedger.ledger` field; the post-Stage-1 access path is
whatever shape PR 2's implementation establishes (PR 2 commit 2
narrows it to a guard wrapper); the post-Stage-4 path is whatever
shape the actor refactor establishes. The ownership distinction
is operational — `PendingTxEngine`
mutates the tracker; `LedgerEngine` owns the ledger state that
the build path reads. `LedgerEngine::balance` is
reservation-agnostic (it answers "what does the ledger say is
mine?", not "what is currently spendable given in-flight
reservations?"); the spendable-balance computation is on
`PendingTxEngine` or `Engine<S>`, not here.

The semantic split between reservation-agnostic and
reservation-aware balance is pinned here for `LedgerEngine`'s
implementation. The structural argument: reservation-aware balance
computation requires reading both ledger state and reservation
tracker state; placing it on `LedgerEngine` would invert the
layering (`PendingTxEngine` consumes `LedgerEngine`, not vice
versa). If `PendingTxEngine` PR's design surfaces reasons to
revisit, the spec distinguishes two paths by §7's additivity
invariants: an *additive* response (e.g., a new
`spendable_balance` method on `LedgerEngine` that reads both
ledger state and the tracker via `Engine<S>`) follows §8.2's
Stage-1-amendment co-landing rule and lands in the consuming PR
without re-opening review; a *non-additive* response that
redefines `balance`'s reservation-agnostic semantic would violate
§7's invariants ("amendments must not change existing method
signatures, async-ness, error type, or ownership semantics") and
re-opens this spec for a new review round per the §8.2 closing
clause. The semantic is pinned as the current best understanding,
not as a permanent invariant.

Per §1.5's actor-identity test, the reservation tracker stays
grouped with `PendingTxEngine` rather than becoming its own actor:
the tracker's consistency requirements bind it tightly to
in-flight transaction bytes and signing state (a tracker actor
crashing independently from a pending-tx actor would leave
reservations referring to transaction bytes that no longer exist),
so isolating it produces no real failure-isolation benefit. This
grouping holds until/unless future evidence demonstrates real
isolation value.

**Stage 1 surface.**

```rust
pub trait LedgerEngine {
    type Error: Into<LedgerError>;

    fn synced_height(&self) -> u64;
    fn snapshot(&self) -> LedgerSnapshot;
    fn balance(&self) -> BalanceSummary;

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
internally; `synced_height`, `snapshot`, `balance` acquire the
read lock. The choice is `RwLock` (not `Mutex`)
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
  (`synced_height`, `snapshot`, `balance`) stay sync
  because Stage 4 implements them via an `Arc<LedgerSnapshot>` the
  actor publishes — readers dereference without queueing on the
  mailbox. Mutations (`apply_scan_result`) are async because
  Stage 4 mutations route through the mailbox and are
  intrinsically async; making them async at Stage 1 locks the
  Stage 4 surface verbatim.

**Stage 1 PR 2 spec-clarification (2026-05-03).** The original §2.2
ownership claim included the reservation tracker, but every other
location in this spec consistently places the tracker under
`PendingTxEngine`: the §2.2 trait surface above defines zero
methods that touch the tracker; §2.4 surfaces `build`/`submit`/
`discard` on `PendingTxEngine` and ties them to the tracker;
§1.5's "Applied to the seven traits" actor-or-not table assigns
the reservation tracker to the `PendingTxEngine` row; §2's Round 3
trait-surface sweep narrative pairs `Mutex<ReservationTracker>`
with `LocalPendingTx`; §3.1's "Stage 1 implementing types" table
describes `LocalPendingTx` as the "new struct wrapping the
reservation tracker" while the `LedgerEngine` row pairs
`LocalLedger` with `WalletLedger` + `LedgerIndexes` only; §3.2
(layered call walk) and §4's idempotency table both treat the
tracker as `PendingTxEngine`-owned. The §2.2 line
was a stale conceptual-ownership artifact and has been corrected
to point readers at §2.4. The amendment additionally pins the
reservation-agnosticism of `LedgerEngine::balance` (previously
implicit) and applies §1.5's actor-identity test to the
reservation tracker, recording why it stays grouped with
`PendingTxEngine` rather than becoming its own actor. No method
signatures or trait shapes change; the §2.2 trait surface block,
the Stage 1 implementing-type note, and the Round 2/Round 3
disposition blocks above are unchanged.

**Stage 1 PR 2 surface narrowing (2026-05-03).** The original §2.2
trait surface declared `fn balance(&self, filter: BalanceFilter)
-> Balance` and `fn transfers(&self, filter: TransferFilter) ->
Vec<TransferDetails>`, naming three types — `Balance`,
`BalanceFilter`, `TransferFilter` — that appeared nowhere else
in the spec, carried no rationale text, and corresponded to no
caller need at PR 2 implementation time. Rust-side reality at the
PR 2 cut-point: `BalanceSummary` already exists in
`shekyl-scanner` as the result type that callers consume from
the existing `BalanceSummary::compute(&[TransferDetails], height)`
helper; no `Balance` type is defined, no `BalanceFilter` /
`TransferFilter` types are defined, and no current consumer
threads a filter argument through any balance or transfers
accessor — the in-tree balance API is `LedgerBlockExt::balance`
(`rust/shekyl-scanner/src/ledger_ext.rs:142`), an extension trait
on `LedgerBlock` whose signature is
`fn balance(&self, current_height: u64) -> BalanceSummary` (a
height parameter, no filter), and consumers reach transfers via
`LedgerBlock::transfers()` on the `WalletLedger.ledger` field
(`rust/shekyl-engine-state/src/ledger_block.rs:231`) which takes
no parameters at all.
Introducing `Balance` as a parallel type alongside `BalanceSummary`
would conflict with `docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`
§7's explicit `BalanceSummary → Balance` rename deferral
("cosmetic; defer to a separate cleanup if naming churn is
wanted"), and introducing empty `BalanceFilter` / `TransferFilter`
placeholder types would import design pressure into PR 2 with no
caller pulling on the filter shape. The amendment narrows the
two signatures accordingly:

```text
- fn balance(&self, filter: BalanceFilter) -> Balance;
+ fn balance(&self) -> BalanceSummary;
- fn transfers(&self, filter: TransferFilter) -> Vec<TransferDetails>;
+ fn transfers(&self) -> Vec<TransferDetails>;
```

This is a non-additive trait-shape change and therefore does not
qualify under §8.2's Stage-1-amendment co-landing rule (which
covers additive method additions only). Per the §8.2 closing
clause, "amendments that violate §7 are not amendments — they
re-open this spec for a new round." The amendment lands as a
focused doc-only PR (the same shape as the 2026-05-03
reservation-ownership amendment block above) so the §7
invariants are honored explicitly rather than by
accident-of-implementation. Filter
types remain available as future *additive* §8.2 amendments when
a concrete consumer surfaces a filter need (e.g.,
`PendingTxEngine`'s output-selection path may want to thread a
`spendable-only` filter; that addition co-lands with the
`PendingTxEngine` PR per §8.2's two-commit form). `LedgerError`
remains as declared — it is a new error enum introduced in PR 2's
commit 1 alongside the trait. The §2.2 ownership claim, lock
choice, async story, balance reservation-agnosticism, and
reservation-tracker actor-identity discussion above are all
unchanged.

**Stage 1 PR 2 transfer-clone discipline (2026-05-03).** The Phase 0b
amendment above (`fn transfers(&self) -> Vec<TransferDetails>`) was
discovered to be unsatisfiable when PR 2's commit 3 (the
`impl LedgerEngine for LocalLedger` block) attempted to construct
the `Vec<TransferDetails>` return value from the underlying
`LedgerBlock::transfers()` slice and `rustc` rejected the call with
`error[E0277]: the trait bound TransferDetails: Clone is not
satisfied`. `TransferDetails` is **deliberately** non-`Clone` per
the type's docstring at
[`rust/shekyl-engine-state/src/transfer.rs`](../rust/shekyl-engine-state/src/transfer.rs):

> Cloning a `TransferDetails` would duplicate its
> `Zeroizing<[u8; N]>` secrets into a second heap allocation that
> the compiler has no way to track. If a caller legitimately needs
> two copies (e.g. a snapshot for a signing round), they must
> `Serialize` into a `Zeroizing<Vec<u8>>` plaintext buffer and
> `Deserialize` back — the process is explicit about the
> secret-handling boundary.

The non-`Clone` discipline is the project's actual privacy/security
policy made manifest in the type system: secrets do not get silently
duplicated. Per
[`.cursor/rules/00-mission.mdc`](../.cursor/rules/00-mission.mdc)
priority 1 ("security and quantum resilience are preconditions"), a
trait surface that requires breaking this discipline is rejected
outright; the precondition is non-negotiable. The
`Vec<TransferDetails>` ownership-transfer signature is therefore
not satisfiable by any implementor that respects the discipline
(and the discipline is, itself, the policy).

**Disposition: drop `transfers()` from the `LedgerEngine` trait
surface.** Three independent grounds:

1. **The discipline is a hard constraint.** Cloning the secrets is
   forbidden; `Serialize`/`Deserialize` round-tripping is the
   documented escape hatch for legitimate two-copy needs (e.g.,
   signing-round snapshots) but is not the right pattern for a
   "give me transfer history" API on every read. Introducing a
   parallel non-secret view type (`TransferSummary` /
   `TransferView`) would solve the compile problem but is a
   substantive design decision (which fields are public, what
   threat models govern that disclosure, what zeroization
   discipline the view type itself requires) that belongs to the
   consumer that requests it, not to a speculative spec
   amendment.
2. **No current Rust caller needs the trait method.** The
   existing transfer-history consumers borrow the
   `LedgerBlock::transfers(&self) -> &[TransferDetails]` slice
   accessor (see
   [`rust/shekyl-engine-state/src/ledger_block.rs`](../rust/shekyl-engine-state/src/ledger_block.rs)),
   which returns a borrowed view rather than an owned `Vec`:
   `shekyl-engine-rpc`'s `scanner_get_transfers` /
   `scanner_incoming_transfers` (gated on the `rust-scanner`
   feature) call `ledger.transfers().iter().filter().map().collect()`
   into `Vec<Value>`; without `rust-scanner` the same RPCs route
   through C++ `wallet2_ffi_get_transfers`. Either way no caller
   asks for owned `Vec<TransferDetails>` from the trait — the
   slice borrow is sufficient and is `Clone`-discipline-respecting
   by construction. Per
   [`.cursor/rules/15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
   ("default: delete") applied at trait-surface granularity, a
   trait method that no caller needs gets removed.

   The asymmetry is worth pinning: when no-caller-needs-it surface
   meets a hard constraint, the disposition tilts toward removal
   rather than preservation. Compare the `Engine::ledger()`
   accessor finding from PR 2's commit 2 pre-flight — also dead
   surface (zero in-tree callers on `dev` today), but PR 2 commit 2
   preserves it via a guard wrapper with a V3.1 `FOLLOWUPS.md`
   audit row because no hard constraint forced a decision. Here
   the `Clone` discipline is the hard constraint that converts
   the default ("delete") from one of several options into the
   only option.
3. **The Stage 4 design space is preserved.** Future re-introduction
   of transfer enumeration on the trait — when a concrete actor
   consumer surfaces the requirement — happens against that
   consumer's threat model rather than speculatively. The
   re-introduced shape is likely a non-secret view type
   (`TransferSummary` or similar) designed against the consumer's
   disclosure needs. This amendment removes a method that cannot be
   implemented without breaking the discipline; it does not
   foreclose the design space that may want to re-introduce
   transfer enumeration later behind a designed view type.

The amendment narrows the §2.2 trait surface accordingly:

```text
- fn transfers(&self) -> Vec<TransferDetails>;
+ (removed)
```

This is a non-additive trait-shape change (removes a method) and
therefore does not qualify under §8.2's Stage-1-amendment
co-landing rule (which covers additive method additions only). Per
the §8.2 closing clause, "amendments that violate §7 are not
amendments — they re-open this spec for a new round." The
amendment lands as a focused doc-only PR (the same shape as the
2026-05-03 reservation-ownership and surface-narrowing amendment
blocks above) so the §7 invariants are honored explicitly rather
than by accident-of-implementation. The §2.2 ownership claim, lock
choice, async story, balance reservation-agnosticism, and
reservation-tracker actor-identity discussion above are all
unchanged; the four-method post-Phase-0c trait surface is
`synced_height` / `snapshot` / `balance` / `apply_scan_result`.

**Cross-references.**

- §1.5 (actor-identity test): `LedgerEngine`'s identity narrows to
  the four-method surface — confirmed-chain projection without
  per-transfer enumeration over the trait. Wallet-internal callers
  reach transfer history through the `LedgerBlock` borrow.
- §7 (out-of-scope discipline): a non-secret view type
  (`TransferSummary` / `TransferView`) is substantively
  out-of-charter for PR 2 and falls under §7's deferral framing;
  future consumers re-introduce the surface when their threat
  model is concrete.
- §8.2 (non-additive amendment): this amendment re-opens §2.2 for
  a new round; it does not co-land under the §8.2 additive-amendment
  rule.

**Pre-flight discipline pattern.** The Phase 0c discovery is
informative for PR 3+'s pre-flight investigations and is worth
pinning as a refinement of the per-trait PR template's "pre-flight
drift expectation" pattern landed in PR #24. PR 2's pre-flight
verified that referenced types existed (`TransferDetails` ✓,
`BalanceSummary` ✓), that signatures aligned with the spec
(return types, parameter shapes), that migration sites were
enumerated (10 sites across 4 files), and that external crate
impact was bounded (`shekyl-engine-rpc`, `shekyl-cli`,
`shekyl-ffi` all unaffected). It did *not* verify whether the
trait's signatures were satisfiable given the implementing types'
existing trait derives, whether the trait's ownership semantics
were compatible with those types' security policies, or whether
existing accessors (`LedgerBlock::transfers` returning a borrow)
suggested the spec's signature should also borrow. The gap
surfaced exactly where the discipline expects it to — at commit 3,
when the impl tried to instantiate the contract and `rustc`
rejected the call. This is the discipline working, not failing:
pre-flight catches structural alignment, compile-time catches
trait-bound implications, review catches semantic drift; all three
are necessary, none alone is sufficient. The "1-2 drifts per
per-trait PR" framing in PR #24's template content covers drifts
that surface at any point during the per-trait PR's lifecycle, not
just pre-flight specifically; this Phase 0c amendment is one such
lifecycle drift. The template language refinement co-lands in PR
2's commit 9 docs propagation per the alt-(c') design-doc
realignment template.

**Cross-doc realignment note.**
[`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](design/STAGE_1_PR_2_LEDGER_ENGINE.md)
predates this amendment and the Phase 0b amendment above, and
carries stale references to the now-removed `Balance` /
`BalanceFilter` / `TransferFilter` types and the now-removed
`transfers()` method in multiple sections:

- §1.2 (Phase 1 implementation overview): trait surface bullet
  lists `transfers` among the read methods.
- §2.1 (Contract vs implementation): the trait method list
  references `transfers`, and the "contract does not pin"
  enumeration references the `Balance` / `BalanceFilter` /
  `TransferFilter` filter types.
- §3.2 (`RwLock<LedgerState>` lock-shape rationale): the readers
  list includes `transfers`.
- §5 (commit-shape table, row 1 "Scope" cell): names `Balance` /
  `BalanceFilter` / `TransferFilter` as commit-1 deliverables.
- §6 (handoff list, `engine/traits/ledger.rs` bullet): names
  the same three filter types and lists `transfers` as part of
  the surface.
- §7 (out-of-scope rename deferral): the
  `BalanceSummary` → `Balance` rename framing is moot
  post-Phase-0b (the rename is no longer required, so the §7
  entry needs refinement rather than the original "defer"
  disposition).

Those references are superseded by this and the prior Phase 0b
amendment. The design-doc realignment co-lands with PR 2 itself,
in PR 2's commit 9 (the docs commit per design doc §5's
nine-commit table), rather than as a separate sidecar PR —
commit 9 is the existing slot for downstream docs effects of the
implementation, and the realignment is exactly such an effect.
The same commit 9 also lands the refinement of PR #24's
"pre-flight drift expectation" template language to cover drifts
that surface throughout the per-trait PR lifecycle (pre-flight,
commit drafting, review feedback) rather than pre-flight alone.
PR 2 reviewers reading commit 1 first should treat the design
doc's filter-type and `transfers()` references as stale until
commit 9 lands the realignment; spec authority over the design
doc means §2.2 above is the binding contract for the
post-Phase-0c surface.

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
the producer-side cancellation checkpoints **2 / 3 / 5** within it,
the scanner construction). Does **not** own the slot, the retry
loop, the inter-attempt cancellation observation, or checkpoints
**1 / 4** — those live on `Engine<S>`. §7 invariant 4 pins the
trait-and-orchestrator checkpoint split as a contract surface; the
five-checkpoint discipline (the new checkpoint 5 = per-transaction
inner check inside the per-block scan loop, per
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
§5.4.9 F2 / F11 / F11-S) is named on the trait surface below and
in §7 invariant 4.

**Stage 1 surface (landed via PR 4 §7.X commits C0–C8 on
`feat/stage-1-pr4-refresh-engine`; the Phase 0a binding form per
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
§4 below is the as-shipped trait).** The trait is now declared at
[`engine/traits/refresh.rs`](../rust/shekyl-engine-core/src/engine/traits/refresh.rs)
(commit `d3edc1abb`, PR 4 C1); the supporting
`RefreshDiagnostic` + `DiagnosticSink` substrate at
[`engine/diagnostics.rs`](../rust/shekyl-engine-core/src/engine/diagnostics.rs)
(commit `8fc207051`, PR 4 C2); the `LocalRefresh` implementor at
[`engine/local_refresh.rs`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)
(commit `ac100e1ab`, PR 4 C4); the `Engine<S, D, L, R>` four-parameter
wiring at
[`engine/mod.rs`](../rust/shekyl-engine-core/src/engine/mod.rs)
(commit `553d70139`, PR 4 C5a); and the
`FaultInjecting<R: RefreshEngine>` + `FaultInjecting<L: LedgerEngine>`
test-substrate wrappers at
[`engine/fault_injecting_refresh.rs`](../rust/shekyl-engine-core/src/engine/fault_injecting_refresh.rs)
(commit `e9310542a`, PR 4 C6α) and
[`engine/fault_injecting_ledger.rs`](../rust/shekyl-engine-core/src/engine/fault_injecting_ledger.rs)
(commit `e94526dec`, PR 4 C6β). The PR 4 §7.X commit list and per-
commit landing-SHA cross-references are in that doc's §7.X header.
The trait as declared:

```rust
pub trait RefreshEngine: Send + Sync + 'static {
    /// Trait-level associated error.
    ///
    /// **Unit-variant-only at the trait surface.** Per
    /// [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    /// §4 Phase 0c and §5.4.7 R6 reframe, the synchronous trait
    /// return is the **structural-branch signal** — the
    /// orchestrator's response to each variant is structural
    /// ("propagate cancellation" / "retry with backoff" /
    /// "rotate peer + do not retry"), not data-dependent. Rich
    /// structured diagnostic information flows through the
    /// `diagnostics: &dyn DiagnosticSink` parameter below (the
    /// second channel of the two-channel actor-mesh seam), not
    /// through the synchronous error payload. Carrying
    /// attacker-influenced data on the error itself
    /// (`String` reasons, daemon-derived evidence buffers) is
    /// rejected per §5.4.7 R6's memory-amplifier-vector closure;
    /// the orchestrator's per-call-site `&'static str` context
    /// for `InternalInvariantViolation` is the only payload
    /// shape that lands at the orchestrator's `RefreshError`
    /// enum, and it is compile-time-fixed developer content,
    /// not attacker-controlled.
    type Error: Into<RefreshError>;

    /// Produce a `ScanResult` against the given ledger snapshot
    /// and daemon.
    ///
    /// # Cancellation
    ///
    /// Owns producer-side checkpoints **2** (post-tip-fetch),
    /// **3** (mid-scan, between blocks), and **5**
    /// (per-transaction, inside the per-block scan loop —
    /// added per
    /// [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    /// §5.4.9 F2 to bound wallet-lock latency under adversarial
    /// daemon block-crafting to per-transaction scan time
    /// rather than per-block scan time). On observation at any
    /// checkpoint, returns `RefreshError::Cancelled`.
    /// Checkpoints **1** (top-of-attempt) and **4** (pre-merge)
    /// are observed by the orchestrator on `Engine<S>`, not
    /// here.
    ///
    /// # Atomicity under cancellation (R7)
    ///
    /// A call returns **either** a `ScanResult` covering the
    /// full span it scanned **or** `RefreshError::Cancelled`.
    /// **No partial-span `ScanResult` is ever returned.** This
    /// is the atomicity contract that lets the orchestrator's
    /// retry loop treat each producer call as a discrete unit
    /// rather than reasoning about partial mid-call state.
    ///
    /// # Checkpoint 5 safe-point pin (F11 + F11-S)
    ///
    /// Checkpoint 5 fires at a **safe-point** — at the top of
    /// the per-transaction iteration in the per-block scan
    /// loop, **after** the prior iteration's `Zeroizing<…>`-
    /// wrapped per-output materials have dropped at scope
    /// exit, and **before** the next transaction's view-tag /
    /// hybrid-decap / key-image derivation begins. Mid-derivation
    /// firing is **forbidden** — the cancellation must not
    /// interleave with a partially-derived per-output secret
    /// whose `Drop` chain has not yet completed. Per
    /// [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    /// §5.4.9 F11-S, implementors **measure**
    /// `recover_outputs_in_tx`'s per-output marginal cost on
    /// reference hardware and escalate the safe-point
    /// granularity to per-output (between consecutive per-output
    /// decap iterations within the per-tx loop, with the same
    /// safe-point semantics) when worst-case per-transaction
    /// scan time under maximum-output hostile transactions
    /// exceeds the §3.1 sub-block lock-latency target.
    ///
    /// # Diagnostic stream
    ///
    /// Structured diagnostic events flow through `diagnostics`
    /// per the two-channel reframe
    /// (§5.4.7 R6 of
    /// [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)).
    /// The synchronous trait return is one channel; the
    /// `RefreshDiagnostic` event stream emitted through this
    /// parameter is the other. The two channels are **coherent**:
    /// every non-`Cancelled` `Err` return is preceded by at
    /// least one corresponding `RefreshDiagnostic` emission
    /// before the error is returned (§5.4.6 emission/return
    /// coherence pin). The `&dyn DiagnosticSink` borrow is
    /// per-call (runtime dispatch; no widening of
    /// `LocalRefresh::new`'s arity at Stage 4 cutover); sink
    /// implementations are **non-blocking** under concurrent
    /// emission and preserve **per-emitter FIFO ordering**
    /// (cross-emitter ordering is undefined). Full-fidelity
    /// `RefreshDiagnostic` consumers MUST be inside the wallet
    /// trust boundary (recursively); cross-process / network-
    /// bound consumers receive only **projection types**
    /// sanitized at the boundary per §5.4.6 / §5.4.8 #4.
    ///
    /// # Daemon-handle borrow
    ///
    /// `daemon` is borrowed for the duration of one attempt.
    /// The `&D` borrow lives only for this call; if the
    /// implementor needs an owned handle to move into a
    /// spawned future (e.g., the parallel block-fetch a future
    /// scaling refinement might add), it clones internally.
    /// The §2.5 `Clone + Send + Sync + 'static` bound on `D`
    /// makes this cheap and Stage-4-actor-compatible
    /// (`ActorRef<DaemonActor>` clones in O(1)). Implementors
    /// MUST NOT borrow `&D` across a `tokio::spawn` boundary;
    /// the borrow-then-spawn pattern would hold the caller's
    /// reference past the call frame, which fails the §1.4
    /// return-value discipline at Stage 4.
    async fn produce_scan_result<D: DaemonEngine>(
        &self,
        snapshot: LedgerSnapshot,
        daemon: &D,
        opts: &RefreshOptions,
        cancel: &CancellationToken,
        progress: &watch::Sender<RefreshProgress>,
        diagnostics: &dyn DiagnosticSink,
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
        .produce_scan_result(snapshot, &daemon, opts, &cancel, &progress, &sink)
        .await?;
    // checkpoints 2, 3, and 5 observed inside produce_scan_result.
    // (Checkpoint 5 is the F2-introduced per-transaction inner
    // check; bounds lock-latency to per-transaction scan time.)

    cancel.check_cancelled()?;          // checkpoint 4: pre-merge
    match self.ledger.apply_scan_result(scan_result).await {
        Ok(())                                   => return Ok(summary),
        Err(RefreshError::ConcurrentMutation)    => continue,
        Err(other)                                => return Err(other),
    }
}
```

**`Send + Sync + 'static` on the trait (Phase 0a; §5.4.6).** PR 1
pinned `Clone + Send + Sync + 'static` on `DaemonEngine` (§2.5)
so the daemon handle is shareable by clone with the producer
task. PR 4 pins `Send + Sync + 'static` on `RefreshEngine`
itself for symmetry: Stage 4's `kameo` actor wraps `LocalRefresh`
as the actor body, and the bound is the type-check predicate
that lets the wrap compile. Listing it at the trait surface
catches the common failure mode where a trait that "happens to
be `Send + Sync + 'static` today" gains a non-`Send` method
parameter (or field) before the actor wrap forces the issue.
The bound is not `Clone`: `RefreshEngine` implementors hold
`ViewMaterial` (secret material; not safely `Clone`-derived per
the architectural-inheritance discipline), so a forced `Clone`
would re-introduce the secret-duplication hazard the
`ZeroizeOnDrop` chain closes.

**`LedgerSnapshot` value-typed contract (Phase 0a; §5.4.5).**
The `snapshot: LedgerSnapshot` parameter is **passed by value**,
not by reference. The orchestrator constructs the snapshot under
the engine read-guard, drops the guard, and hands the snapshot
to the producer by move. `LedgerSnapshot` carries only
reorg-window descriptors (block hashes plus per-height summaries)
— no shared state, no lifetime tying it to the live ledger;
cheap clone is honest because the type carries no shared
state. The contract pin prevents future drift toward
`&LedgerSnapshot` shapes that would hold a borrow across the
unlocked scan phase (a `&mut LedgerEngine`-equivalent
talking-stick handoff in disguise per §1.4).

**`ViewMaterial` (Phase 0a; per
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
§5.4.7 R4 — a-instance-scoped).** A new public type in
`shekyl_engine_core`, exported at the flat crate root alongside
`RefreshError` / `RefreshOptions` / `RefreshProgress`:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ViewMaterial {
    pub spend_pub: EdwardsPoint,
    pub view_scalar: Zeroizing<Scalar>,
    pub x25519_sk: Zeroizing<[u8; 32]>,
    pub ml_kem_dk: Zeroizing<Vec<u8>>,
    pub spend_secret: Zeroizing<[u8; 32]>,
}
```

`LocalRefresh::new(view_material: ViewMaterial)` captures the
view-and-spend material at construction time; the `Scanner`
builds once at `LocalRefresh::new` and is held for the
instance's lifetime. Per-attempt cost drops to
`(snapshot.clone() + daemon.get_height() + per-block
fetch+scan)` — no per-attempt scanner construction, no
per-attempt secret duplication. Pinning the type at the
trait-surface site so Stage 4 actor implementors and any
future `RefreshEngine` implementor share the constructor
shape; the (a-instance-scoped) lifetime story is the
trait-surface contract, not a `LocalRefresh`-specific
implementation detail.

**Borrow-checking story.** This shape sidesteps the original Q9.7
problem cleanly. The producer takes:

- An owned `LedgerSnapshot` (cheap clone of reorg-window
  descriptors; not a borrow on the ledger).
- A borrowed `&D: DaemonEngine` (lives for one attempt; the
  implementor clones internally if it needs an owned handle).
- Borrowed cancel / progress / diagnostic-sink channels (the
  `&dyn DiagnosticSink` borrow is per-call and runtime-dispatched
  so Stage 4 does not re-rev the trait or widen
  `LocalRefresh::new`'s arity when a new sink type emerges).

No `&mut LedgerEngine` is held anywhere on the trait surface
(per Round 3's §2 sweep: all trait methods are `&self` with
interior mutability in implementing types). The orchestrator
holds `&LedgerEngine` for the brief snapshot read and the brief
merge call; both calls acquire the implementing type's internal
lock for the duration of one method invocation. No long-held
borrow across the unlocked scan phase, no caller-provided
mutation handle, no talking-stick handoff — exactly the discipline
§1.4 enforces, now expressed at the trait boundary.

**Phase 0 substrate (design provenance).** The §2.3 surface
above lands in two stages:

- **Phase 0a (this section, doc-only)** — the
  Phase-0a-binding-pinned trait surface per
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §4: `Send + Sync + 'static` supertrait bound, unit-variant
  `Self::Error: Into<RefreshError>` discipline, six-arg
  `produce_scan_result` with the `diagnostics: &dyn
  DiagnosticSink` parameter, `LedgerSnapshot` value-typed
  contract, `ScanResult` atomicity-under-cancellation
  contract (R7), `ViewMaterial` type pin (R4
  a-instance-scoped), and the five-checkpoint discipline
  (F2 / F11 / F11-S).
- **Phase 1 (Stage 1 PR 4's C1–C8 commits)** —
  `pub(crate) trait RefreshEngine` lands in
  `engine::traits::refresh`; `ViewMaterial` /
  `RefreshDiagnostic` / `DiagnosticSink` /
  `NoopDiagnosticSink` / `TracingDiagnosticSink` /
  `LocalRefresh` ship as the Stage 1 concrete substrate;
  `Engine<S, D, L, R>` parameterization wires the trait
  into the orchestrator. The §7.X commit decomposition
  ordering is load-bearing for the Phase 1
  bisection-discipline gate.

Stage 4 cutover preserves the §2.3 surface verbatim per §7's
invariants; the implementor swap (`LocalRefresh` →
`kameo`-backed actor body) does not touch the trait shape.

### 2.4 `PendingTxEngine`

**Reframed across Round 2 segments 2b–2g (binding-form pins) and
Round 2 segment 2h / 2i (post-Round-3-readiness state-shape
refinement + wider-ecosystem-lessons substrate).** The
Round 1 surface stub (four-method trait; `Self::Error`-only
return shape; opaque ownership of a `BTreeMap`-shaped reservation
tracker) closes against the Round 2 / Round 3 design substrate
pinned in
[`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§4 (Phase 0a–0m binding-form enumeration), §5.0.1 (the (γ) lean
state shape), §5.0.2 (the diagnostic-stream + enum block), and
§5.0.3 (the seven cross-cutting `DiagnosticSink` contracts). The
surface below is the as-designed Stage 1 trait shape; the §7.X
commit decomposition in the design doc records the eight-commit
landing plan (C0–C8) for the `feat/stage-1-pr5-pending-tx-engine`
short-lived branch.

**Ownership.** The (γ) lean state shape per
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§5.0.1: three collections (`output_locks: HashMap<OutputId,
ReservationId>` reservation-output lock map; `consumer_held:
HashMap<ReservationId, Instant>` post-build / pre-submit
reservations awaiting consumer-side `submit` or `discard`;
`in_flight: HashMap<ReservationId, InFlightSubmit>` reservations
whose `submit` has dispatched to the daemon and is awaiting
resolution) and a `current_snapshot: SnapshotId` field; plus a
monotonic `next_reservation_id: u64` counter. The reservation's
lifecycle is encoded by collection membership, not by a
`ReservationState` enum (the segment-2g enum disposition was
dissolved into collection membership in segment 2h per the
"refusal-forever vs. reject-with-reopening-criteria" framing in
[`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc);
see §5.6.2 of the design doc for the substrate). The
build / submit / discard state machine surfaces externally via
the trait below; the `signal_mempool_evicted` method (Phase 0m,
segment 2i) admits a narrow consumer-observed mempool-eviction
signal per the F2 ownership-boundary adjudication discipline.

**Stage 1 surface (Round 3-closed; landed via PR 5 §7.X commits
C0–C8 on `feat/stage-1-pr5-pending-tx-engine`; implementation tip
`ca7622558` at C7, C8 doc commit follows).** The trait is
declared at
[`engine/traits/pending_tx.rs`](../rust/shekyl-engine-core/src/engine/traits/pending_tx.rs)
(PR 5 C5α = `ecc86c741`); the supporting `SubmitError` /
`TerminalErrorKind` / `AmbiguousErrorKind` / `PendingTxError` /
`DiscardReason` / `SnapshotId` / `ReservationExtension` /
`PendingTxDiagnostic` enums + the augmented `Reservation` /
`PendingTx` types land in `engine/error.rs` /
`engine/diagnostics.rs` / `engine/pending.rs` (PR 5 C2 =
`fa5981e9d` / `316f5c15e` / `8f8e4c863`; C3 = `58fb6174f`); the
`LocalPendingTx<S: Signer, O: OutputSelector, F: FeeEstimator>`
aggregate implementor lands at
[`engine/local_pending_tx.rs`](../rust/shekyl-engine-core/src/engine/local_pending_tx.rs)
(PR 5 C5β = `a137cc234`); the `Engine<S, D, L, R, P>` five-
parameter wiring lands in `engine/mod.rs` (PR 5 C6 =
`0713591bf`).
The trait surface (Phase 0a + 0e + 0f + 0m binding form) is:

```rust
pub trait PendingTxEngine: Send + Sync + 'static {
    /// Build a pending transaction against the current ledger
    /// snapshot; reserves the selected inputs in `consumer_held`
    /// and returns the `PendingTx` handle to the caller.
    ///
    /// # Errors
    ///
    /// Returns `SendError` for build-time validation failures
    /// (insufficient funds, no spendable outputs, selector
    /// rejected the request, fee estimator unavailable, etc.).
    /// Per the Round 2 Q9.8 closure (kept), `SendError` is the
    /// build-time vocabulary; runtime invariants surface through
    /// `PendingTxError` on later trait calls.
    async fn build(
        &self,
        request: TxRequest,
    ) -> Result<PendingTx, SendError>;

    /// Submit the named reservation to the daemon.
    ///
    /// **Collection-move discipline (segment-2h P4 table).** On
    /// entry, `rid` MUST be in `consumer_held` (else return
    /// `SubmitError::ReservationNotFound` or
    /// `SubmitAlreadyPending` per the P3 / P2 discriminating
    /// switch). On `submit` dispatch, the rid moves from
    /// `consumer_held` to `in_flight`; on daemon resolution, the
    /// rid either (a) drops from `in_flight` on
    /// `TerminalErrorKind` outcomes (and the engine emits
    /// `Discarded { rid, DaemonRejectedTerminal { kind } }`), or
    /// (b) stays in `in_flight` on `AmbiguousErrorKind` outcomes
    /// (R9 daemon-side-authority per Finding 2; the engine emits
    /// `SubmitPendingResolution { rid, tx_hash, kind }`), or (c)
    /// drops from `in_flight` on accept (and the engine emits
    /// `SubmitSucceeded { rid, tx_hash }`).
    ///
    /// **Staleness check (segment-2h F1 pin).** Before dispatching
    /// to the daemon, the handler reads `current_snapshot` (Stage 1
    /// reads exact ledger truth under the
    /// `Mutex<PendingTxState>` guard; Stage 4's actor-local view
    /// is best-effort under mailbox-FIFO ordering against
    /// `LedgerDiagnostic::SnapshotMerged` arrivals) and compares
    /// against the reservation's `snapshot_id`. On mismatch:
    /// **lazy R5 disposition (segment 2h)** — the engine emits
    /// `SubmitSnapshotInvalidated { rid, reservation_snapshot,
    /// current_snapshot }`, returns
    /// `SubmitError::SnapshotInvalidated`, and **does NOT
    /// auto-release** the reservation; the consumer must call
    /// `discard(rid, ConsumerExplicit)` to release
    /// `output_locks`. R8 TTL safety-net handles consumer
    /// abandonment.
    ///
    /// **Stage 4 multi-step decomposition (segment-2i G4 pin).**
    /// Under Stage 4, the handler decomposes into a three-step
    /// self-continuation pattern (`submit_start` →
    /// `submit_signed` → `submit_completed`) with **deferred-reply
    /// semantics** to absorb the HW-wallet signing-latency window
    /// and the daemon-round-trip window without blocking the
    /// actor's main mailbox. The Stage 4 actor-migration PR's
    /// framework-selection pre-flight MUST confirm deferred-reply
    /// substrate support per the
    /// [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
    /// §5.0.1 G4 pin; if no candidate framework supports it, G4's
    /// disposition reopens at the framework-selection altitude
    /// (NOT retroactively against PR 5; PR 5's V3.0 trait surface
    /// stays synchronous regardless).
    async fn submit(
        &self,
        id: ReservationId,
    ) -> Result<TxHash, SubmitError>;

    /// Discard the named reservation with an explicit reason.
    ///
    /// **F2 ownership-boundary discipline (segment-2h pin).**
    /// Consumer-initiated `discard` on a reservation in
    /// `in_flight` returns
    /// `PendingTxError::DiscardBlockedPendingDaemonAck`; the
    /// daemon owns the resolution authority while the rid is
    /// `in_flight` (Finding-2 ambiguous-outcome handling). On
    /// `consumer_held` rids, the handler atomically removes the
    /// rid from `consumer_held`, releases `output_locks` for the
    /// rid, and emits
    /// `Discarded { rid, reason }`.
    fn discard(
        &self,
        id: ReservationId,
        reason: DiscardReason,
    ) -> Result<(), PendingTxError>;

    /// Signal that a previously-submitted reservation's tx has
    /// been observed evicted from the daemon's mempool (Phase 0m
    /// per segment-2i G1 disposition).
    ///
    /// **F2 ownership-boundary adjudication (segment-2i G1 pin).**
    /// Mempool eviction is an *observation* the consumer made
    /// that the actor couldn't make itself (the actor has no
    /// direct visibility into the daemon's mempool state); the
    /// observation is *of a state already terminal at the
    /// network level* (the tx is gone from the mempool; the
    /// daemon will never `Accept` it). The signal admits one
    /// specific observation under F2; it does NOT admit
    /// consumer-side terminal *decisions* (a hypothetical
    /// `signal_user_force_cancel` shape that F2 forbids). The
    /// narrow-vs-wide method-shape question is adjudicated
    /// per-method: each new "consumer signals terminal"
    /// candidate gets its own narrow method and its own F2
    /// adjudication entry. A wider
    /// `signal_external_terminal(rid, reason)` shape would
    /// silently admit decision-class signals; the narrow shape
    /// preserves the per-method F2 adjudication grep-ability
    /// that the wider shape forecloses. See
    /// [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
    /// §5.6.10 G1 for the full F2 adjudication record.
    ///
    /// On success: the rid drops from `in_flight`,
    /// `output_locks` are released for the rid, and the engine
    /// emits `Discarded { rid, reason:
    /// DiscardReason::MempoolEvicted }` (all within a single
    /// P7-atomic handler step). Returns
    /// `PendingTxError::ReservationNotFound` if `rid` is not in
    /// `in_flight` — including rids in `consumer_held`
    /// (eviction is meaningful only for in-flight reservations;
    /// consumer-held reservations were never submitted to the
    /// daemon).
    fn signal_mempool_evicted(
        &self,
        rid: ReservationId,
    ) -> Result<(), PendingTxError>;

    /// Total in-process reservations awaiting resolution. Sum of
    /// `consumer_held.len() + in_flight.len()` per the (γ) lean
    /// state shape.
    fn outstanding(&self) -> usize;
}
```

**`Send + Sync + 'static` on the trait (parallel to §2.3 / PR 4
precedent).** The supertrait bound supports the Stage 4
`kameo`-equivalent actor wrap of `LocalPendingTx` as the actor
body. Listing it at the trait surface catches the common failure
mode where a trait that "happens to be `Send + Sync + 'static`
today" gains a non-`Send` field (a `Signer` impl holding a
non-`Send` HSM handle, a `FeeEstimator` impl holding a non-`Send`
RPC client) before the actor wrap forces the issue. The bound is
**not** `Clone`: `LocalPendingTx` holds `Arc<S: Signer>` (spend
material; not safely `Clone`-derived per the architectural-
inheritance discipline per
[`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)),
so a forced `Clone` would re-introduce the secret-duplication
hazard.

**Trait-parameter slots and constructor-bound dependencies.**
The implementor (`LocalPendingTx<S: Signer, O: OutputSelector,
F: FeeEstimator>`) is parameterized on three trait surfaces from
the Phase 0h / 0i / 0j enumeration; a fourth constructor parameter
binds the diagnostic-stream sink (`sink: Arc<dyn DiagnosticSink>`,
segment-2f §5.0.2.1 sink-binding closure). The constructor also
takes the `ReservationTTLConfig` (Phase 0l per-collection TTL;
both fields default to `DEFAULT_RESERVATION_TTL`, per-collection
shape per F7 disposition) and the `LedgerEngine` handle for
`current_snapshot` reads at submit-time. Stage 4's `PendingTxActor`
preserves the trait-parameter taxonomy via spawn-time DI
(`signer: ActorRef<SigningActor>`, `output_selector: Arc<dyn
OutputSelector>`, `fee_estimator: Arc<dyn FeeEstimator>`); the
trait surface is identical across both stages.

**Stage 1 implementing-type note (Round 3 + segment 2h).**
`LocalPendingTx` holds `Mutex<PendingTxState>` for interior
mutability over the (γ) three-collection shape. All mutating
calls (`build`, `submit`, `discard`, `signal_mempool_evicted`)
acquire the mutex internally per the **handler-atomicity
discipline (P7 pin)**: lock claim/release on `output_locks` +
collection insert/remove on `consumer_held` / `in_flight` + sink
emit all run within a single guard window; no `.await` between
mutation steps. `outstanding` reads through the mutex briefly.
The choice remains `Mutex` (not `RwLock`) because
`PendingTxEngine`'s operations are predominantly write-style —
even `outstanding` is a read against state that mutates on every
other call. Stage 4's `ActorRef<PendingTxActor>` provides
equivalent serialization through its mailbox; the
handler-atomicity discipline is satisfied by performing all
mutations synchronously within the handler before yielding to
the mailbox.

**Round 3 disposition (the &mut → & sweep).** Originally `&mut
self` on `build`, `submit`, `discard`; revised to `&self` per the
§2 `&mut → &self` sweep. Same rationale as §2.2's
`apply_scan_result` change: Stage 4's `ActorRef<…>` cannot satisfy
`&mut self`. Interior mutability in `LocalPendingTx` (the Stage 1
type) replaces compile-time borrow checking with runtime mutex
serialization; Stage 4's mailbox replaces the runtime mutex with
message FIFO. The trait surface is identical across both stages.
`signal_mempool_evicted` (added in segment 2i, post-sweep) is
`&self` by construction.

**Concrete return types (segment-2h `Self::Error` retirement).**
The trait no longer declares an associated `Error` type. The
original `type Error: Into<PendingTxError>` shape conflated the
build / submit / discard / signal_mempool_evicted error
vocabularies behind a single associated type; the segment-2h
reshape split the vocabularies (`SendError` for build, `SubmitError`
for submit, `PendingTxError` for discard /
`signal_mempool_evicted`) and concrete-typed each return. The
type system now enforces the lifecycle-class distinction
(`TerminalErrorKind` vs. `AmbiguousErrorKind` inside
`SubmitError`; `DiscardBlockedPendingDaemonAck` vs.
`ReservationNotFound` inside `PendingTxError`) without consumer-
side wildcard matching. See
[`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
§5.0.2 for the enum block; §5.6.4 / §5.6.5 / §5.6.6 for the
P-discipline and F-discipline substrate.

**Round 2 dispositions (preserved).**

- **Q9.8 (`build` returns `SendError` vs. `Self::Error`): closed
  keep `SendError`.** The split exists because `SendError`
  covers build-time validation (insufficient funds, no spendable
  outputs, selector contract violation per F4); `PendingTxError`
  covers runtime invariants (discard-side / signal-side
  classification). The two vocabularies are distinct domains;
  collapsing them would force callers to discriminate by variant
  rather than by error type.
- **Q9.9 (V3.1 multisig methods inclusion): closed not in Stage 1
  surface; additive at Stage 4.** `inspect`, `adjust_fee`,
  `sign_partial` from the *Pending-tx protocol* decision-log entry
  are V3.1+ multisig concerns; Stage 4's actor-shaped trait
  implementation can add them without re-opening the §2.4 surface.

**Phase 0 substrate (design provenance).** The §2.4 surface
above lands in two stages:

- **Phase 0 (this section, doc-only)** — the Phase 0a–0m
  binding-form pins per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §4: `Send + Sync + 'static` supertrait bound; concrete-typed
  return shapes (`SendError` / `SubmitError` / `PendingTxError`);
  five-method trait surface (`build` / `submit` / `discard` /
  `signal_mempool_evicted` / `outstanding`); the supporting
  `TerminalErrorKind` + `AmbiguousErrorKind` + `SubmitError` +
  `PendingTxError` + `DiscardReason` + `SnapshotId` +
  `ReservationExtension` + `PendingTxDiagnostic` enums; the
  `OutputSelectorError::ReturnedIndicesNotSubset` F4-enforcement
  variant; the `ReservationTTLConfig { consumer_held, in_flight
  }` per-collection TTL substrate; the `Signer`, `OutputSelector`,
  and `FeeEstimator` trait surfaces (Phase 0h / 0i / 0j); the
  `SubmissionStrategyActor` topology slot (Phase 0k; V3.0-
  reserved, V3.x-introduced); the `LedgerDiagnostic::SnapshotMerged`
  variant stub (Phase 0g; deferred to V3.x consumer-actor PR per
  segment-2g closure). C0 lands as the doc-only Phase 0 spec
  amendment per the §7.X commit decomposition.
- **Phase 1 (PR 5 §7.X commits C0–C8 — landed 2026-05-27)** —
  `pub trait PendingTxEngine` landed in
  `engine::traits::pending_tx` (C5α); the enum families and
  augmented `Reservation` / `PendingTx` types shipped in
  `engine::pending` / `engine::error` / `engine::diagnostics`
  (C2/C3); `LocalPendingTx<S, O, F>` shipped as the Stage 1
  concrete substrate (C5β); `Engine<S, D, L, R, P>` five-
  parameter wiring rewired orchestration-layer dispatch to
  delegate through `P: PendingTxEngine` (C6); `FaultInjecting<P>`
  + C7 property tests shipped under `test-helpers` (C7). The
  §7.X commit decomposition ordering was load-bearing for the
  Phase 1 bisection-discipline gate; segment-2h within-commit
  deltas (§5.6.8) and segment-2i delta-on-delta (§5.6.12) are
  reflected in the landed code, not the pre-segment-2h
  `ReservationState` / `SubmitFailed` shapes in older §7.X prose.
  Locator: [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §6 landing-SHA table.

Stage 4 cutover preserves the §2.4 surface verbatim per §7's
invariants; the implementor swap (`LocalPendingTx` → `kameo`-
backed `PendingTxActor` body) does not touch the trait shape.
The Stage 4 multi-step submit + deferred-reply substrate-
confirmation pin (segment-2i G4) lives at the actor-migration PR's
framework-selection pre-flight, not at this trait surface.

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
itself, never on `Rpc`. The test-support mock implements `Rpc`
directly (rather than wrapping `SimpleRequestRpc`) and carries an
`impl DaemonEngine for MockDaemon` that satisfies the trait
contract — including the `submit_transaction` per-tx-hash dedup
clause from §6.1 and the fee-estimate / submit error-queue surface
that producer-and-driver tests inject failures through. The mock
is `MockDaemon` in
[`engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs)
(renamed from `MockRpc` when its surface widened to a full
`DaemonEngine` implementor in Stage 1 PR 1).

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

**External validation (Round 4a — Item 20).** The
canonical-derivation framing addresses a class of failure
observed across crypto economies where scattered economic
computations produce divergent results — fee-only fragility,
adaptive-policy drift between consumers, governance-token
parameter inconsistency. The economic *design* that
`EconomicsEngine` consumes — transaction-responsive release,
adaptive burn, decaying staker emission share — is documented
in [`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) and
[`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md);
the trait spec implements the structural shape that makes the
economic design enforceable and auditable inside the wallet.
The trait spec does not re-articulate the economic design; it
consumes it.

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

**Consensus-as-truth: explicit pin (Round 4a — Item 3).**
`EconomicsEngine` vends derived values that are also
computable from chain state by any other wallet implementation.
**Wallet-side enforcement of consensus rules is out of scope
and out of charter; the chain is the source of truth for
cross-engine eligibility** (e.g., "stakers must archive,"
"archivers must stake," activation thresholds, slashing
conditions, parameter-update activation timing).

Three reasons this pin is load-bearing for the spec:

1. **Cryptocurrency-correctness.** Wallet-side enforcement of
   consensus rules is meaningless because alternative wallets
   won't enforce it and the chain accepts whatever consensus
   accepts. A wallet that "enforces" rules the chain doesn't
   creates the illusion of safety while providing none. The
   MMORPG analogy understates this: in an MMORPG, client-side
   enforcement is bypassable but the game can still function
   with cheaters; in a cryptocurrency, the chain is the only
   layer that matters for consensus rules. Anything on the
   client computer is suspect to the network.
2. **Scope-discipline.** `EconomicsEngine`'s charter is
   *canonical derivation* — a single source of truth for
   computing values from parameters and chain state.
   Orchestration of cross-engine invariants is a distinct
   responsibility, and folding it into `EconomicsEngine`
   would re-introduce the supertrait-composition pattern
   that §2.7's *consumers, not subsumes* framing rejected,
   plus a kameo-foreign multi-actor coordination shape at
   Stage 4.
3. **Bug-class prevention.** The Bug 2 / 7 / 13 class
   `EconomicsEngine` exists to prevent is *scattered
   canonical derivation*. Adding orchestration would extend
   the trait's responsibility into *cross-engine
   enforcement*, which is a different bug class with a
   different correct home (consensus rules in
   `shekyl-consensus`, not wallet code).

The cross-engine coupling questions for Phase 2b's
`StakeEngine` design are pinned in §10's deferred subsection:
the design must specify whether "stakers must archive" is
consensus-enforced (chain rule), economics-incentivized (no
hard rule, math makes the right behavior emerge), or
wallet-orchestrated. The Round 3 / Round 4a `EconomicsEngine`
canonical-derivation framing assumes consensus-or-incentive;
if Phase 2b's design surfaces a wallet-orchestration
requirement, `EconomicsEngine`'s role expands and the trait
surface is revisited at that point — but the consensus-as-truth
principle remains the spec-level default.

**Scope guard for `EconomicsEngine` (Round 4a — Item 19).**
The recurring-pattern observation that prompted this guard:
two distinct framings have proposed pulling `EconomicsEngine`
outside its proper scope (orchestrator-as-cross-engine-enforcer
in Round 3; failure-mode-contrast-surface in Round 4a). The
named scope is:

> `EconomicsEngine` is a wallet-side canonical-derivation
> surface for chain-derived values; it is **not** the place for
> consensus enforcement, network-wide observability, or
> economic-rationale documentation. Consensus enforcement lives
> in `shekyl-consensus`; network-wide observability lives in
> chain RPC consumed via `DaemonEngine` or in tracing-based
> observability per §3; economic rationale lives in
> [`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md).

Future proposals that would extend `EconomicsEngine` into any
of those territories require explicit revisit of this scope
guard, not silent extension. See §1.5's scope-guard
meta-pattern for the broader discipline this instance
participates in.

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

    /// Parameter snapshot for governance / display.
    ///
    /// At V3.0 the snapshot is constants-derived and stable in
    /// practice. At V3.x Component 3 the snapshot reflects the
    /// current adaptive-burn state and may change between
    /// calls.
    ///
    /// **Callers must not cache the snapshot beyond the
    /// immediate use.** Even at V3.0 where the value is stable,
    /// the contract permits per-call variation; callers that
    /// cache the snapshot break at V3.x adoption. Treat each
    /// call as fresh; if you need stability across a logical
    /// operation, capture the snapshot at the start of the
    /// operation and use that captured value for its duration,
    /// then discard.
    ///
    /// This is the same forward-compatibility discipline as
    /// §3.4's drop-cancellation: write Stage-4-ready code at
    /// Stage 1 and V3.x-ready code at V3.0.
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

**Discipline test for new methods on `EconomicsEngine`
(Round 4a — four clauses + consumer-driven justification).**
New methods proposed for this trait must satisfy both:

- **All four clauses (a)/(b)/(c)/(d) below**, AND
- **A named consuming trait that drives the addition** (Round
  4a — Item 17). Proposals lacking a named consumer are
  rejected as speculative; speculative additions accumulate
  trait surface that no consumer needs and that future
  consumers may have to work around. The named-consumer rule
  is workflow discipline, not just ergonomic discipline:
  a method addition that names "Phase 2b's `StakeEngine`
  needs `pool_weighted_total_at_height(height) -> u128` for
  historical-yield queries" is a legitimate proposal; a
  method addition that says "this might be useful to expose"
  is not.

The four clauses:

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
4. **The result is a function of inputs and observable state,
   not of caller-provided context** (Round 4a addition) — the
   method's correctness must not depend on per-entity state
   lookup. A method that takes a `StakeId`, `ShardId`, or
   account-keyed selector and returns a value derived from
   that entity's state fails this clause regardless of how
   the parameters look syntactically. *Worked example:*
   `yield_for_stake(stake_id) -> u64` looks like canonical
   derivation but is actually `StakeEngine` territory: the
   correctness of the return value depends on per-stake state
   (lock tier, principal, accrued rewards) that the
   `EconomicsEngine` does not own. The canonical-derivation
   shape is `EconomicsEngine::stake_yield_rate(lock_tier,
   pool_total) -> u64` (parameters and snapshot inputs), not
   `EconomicsEngine::yield_for_stake(stake_id) -> u64` (entity
   selector).

This discipline prevents `EconomicsEngine` from accreting
domain-specific state (per-stake, per-shard,
per-archival-portfolio) that would defeat the
dependency-not-subsumption shape and re-introduce the Bug 2 /
7 / 13 class via "this method combines economics with
X-specific state" surface pollution. Clause (d) makes the
StakeEngine / EconomicsEngine boundary mechanically testable
rather than relying on reviewer judgment: any method whose
parameter list contains an entity selector belongs on the
consuming trait, not on `EconomicsEngine`. Reviewers proposing
methods that fail any of the four criteria should re-target
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
`LocalRefresh`, `DaemonClient`, `LocalEconomics`).

**Stage 1 destructor independence (Round 4a — Item 7
softening, supersedes the Round 3 "drop matches teardown"
claim).** Stage 1 trait fields hold owned state with no
teardown-time inter-dependency: each destructor cleans up its
own state without calling into other trait fields. `WalletFile`'s
`Drop` flushes pending writes and closes the file handle without
reading from `LocalLedger`; `AllKeysBlob`'s `ZeroizeOnDrop`
clears key material without coordinating with anyone;
`LocalLedger`'s `Drop` frees in-memory state without writing to
`WalletFile`. Drop in any order is correct because the
destructors are *individually correct*, not because the order
happens to match a teardown graph.

The teardown graph (§2.8.5) becomes load-bearing only at
**Stage 4** where actor `stop_gracefully` cascades have
ordering requirements (Persistence absorbs Ledger's final
flush before closing; Ledger waits for Refresh and PendingTx
to release their handles). At Stage 4, `Engine::close`
orchestrates the ordered teardown explicitly per §2.8.6's
drop-vs-close asymmetry; relying on field-declaration drop
order would be incorrect because Stage 4 actors *do* have
inter-actor cleanup dependencies that drop alone cannot
satisfy.

Round 3's claim that "declaration order on `Engine<S>` mirrors
dependency-reverse … so that drop matches the teardown graph"
conflated two distinct properties: *independent destructor
correctness* (Stage 1) and *ordered teardown coordination*
(Stage 4). The properties are different; flattening them under
a single "drop matches teardown" framing read as comforting but
was over-strong. The Round 4a softening separates them: Stage 1
relies on independence; Stage 4 relies on `Engine::close`'s
orchestrated cascade.

The field declaration order on `Engine<S>` (per §3) is a
*type-parameter ordering* decision (dependency-leaves first,
compound traits last; narrative-coherent ordering within each
group), not a Drop-order decision. Two different orderings
doing different jobs.

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

**Decision (Round 4a, reverses Round 3 lean): async-public.** At
Stage 4 `Engine::create` (and the `open_*` constructors) returns
`impl Future<Output = Result<Engine<S>, EngineError>>`; callers
absorb `await` at construction. Three reasons the Round 3 lean
toward sync-public-via-`Handle::block_on` does not survive review:

1. **§7's invariant scope is trait surfaces, not inherent methods.**
   §7.1 names "the trait method signatures in §2"; lifecycle
   methods are inherent on `Engine<S>`, not trait methods. The
   "trait surface doesn't change at Stage 4" discipline does not
   extend to inherent methods. Round 3's sync-public lean
   implicitly extended it; Round 4a corrects the over-extension.
2. **Async-native operation forced through a sync boundary is
   contortive.** The spawn graph below is `tokio::try_join!` over
   actor spawns — async-native by construction. Wrapping it in
   `Handle::block_on` to expose a sync surface, then immediately
   re-entering async at the trait calls inside, carries the
   multi-thread-runtime precondition cost (per §4.2) without the
   ergonomic justification. `Engine::refresh` justifies the
   pattern because it is hot-path and called from sync contexts
   that genuinely cannot restructure; `Engine::create` is one-shot
   at startup and its callers are binary entry points that can
   absorb async with no friction.
3. **Library-embedding compatibility.** A library consumer that
   wants to construct an `Engine` without first setting up a
   multi-thread tokio runtime cannot, under the Round 3 lean,
   because sync-public-via-`Handle::block_on` requires one.
   Async-public `Engine::create` lets the consumer choose: their
   own runtime, `tokio::main`, or `block_on` at the call site if
   they truly need sync. This is the same discipline V3.0's
   internal binaries already follow; making it the public surface
   matches the contract to the actual call-pattern.

**The Stage 1 → Stage 4 signature change is documented as a known
divergence with rationale.** Stage 1's `Engine::create` is sync
(no actors to spawn, all construction is in-process). Stage 4's
`Engine::create` is async (actor spawn graph is async-native).
Callers that move from Stage 1 to Stage 4 add `.await` at the
construction call site. This is a one-shot adjustment at binary
startup; it does not propagate through hot paths. The adjustment
is named in `CHANGELOG.md` at the Stage 4 cutover so consumers
know to expect it.

**The §4.2 multi-thread-runtime precondition does not extend to
`Engine::create`.** §4.2's precondition exists for
`Engine::refresh`, which uses `Handle::block_on` internally to
preserve its sync surface. Async-public `Engine::create` does not
use `Handle::block_on`; it runs on whatever runtime the caller
provides. A single-thread runtime can drive `tokio::try_join!`
correctly because join is at the scheduler level, not the
`block_on` level. The multi-thread-runtime precondition stays
where it lives today (`Engine::refresh`'s rustdoc).

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

Per-actor spawn timeouts are configurable via
`EngineConfig::spawn_timeouts: SpawnTimeouts` (per §2.8.8); the
struct carries one `Duration` per actor with a 5-second default
across the board. Spawn timeout exceeded → partial-construction
failure → cleanup cascade per §2.8.5.

**Why 5s default (estimate, not measurement).** The 5-second
default is an **estimate** based on covering pathological-case
latency for the slowest legitimate operations: cold-cache disk
I/O for `PersistenceEngine` (encrypted wallet file read), TLS
handshake for `DaemonEngine` (against a possibly-distant peer),
and Argon2id KDF for `KeyEngine` (with conservative parameters).
The estimate is *revisable based on field data*; the spec does
not pretend the 5s is empirically measured.

The user-visible failure mode at 5s is a clear "couldn't open"
rather than an indefinite spinner; that's the design goal. If
field data shows legitimate slow paths exceeding 5s on
constrained devices (low-end phones, embedded systems with
slow flash), the per-actor defaults extend or callers configure
overrides via the builder pattern in §2.8.8 — no recompile
required.

**Why per-actor over uniform.** The three pathological-latency
distributions are different: slow disk vs. slow network vs.
slow CPU manifest as different bug patterns at the failure
boundary. A uniform timeout that fires identically across all
three loses diagnostic information at the failure boundary
("which actor was slow?"); per-actor timeouts let the failure
mode be specific. Per-actor with `#[non_exhaustive]` builder
overrides preserves the specificity while letting callers
override individual fields ergonomically (see §2.8.8 for the
`SpawnTimeouts::with_<actor>` pattern).

**Configurability surface (Round 4a — Item 12 pin).**

| Aspect | Resolution |
|---|---|
| Config field | `EngineConfig::spawn_timeouts: SpawnTimeouts` (per §2.8.8) |
| Per-actor vs uniform | Per-actor (one `Duration` per trait); uniform is rejected on diagnostic-information grounds |
| Override mechanism | Builder pattern: `SpawnTimeouts::default().with_daemon(d)…` (per §2.8.8 sketch) |
| Default-vs-custom | `Default` impl returns 5s for every field; callers override via builder |
| Empirical revisability | The 5s default is documented as an estimate; revisable based on V3.x field-data without spec amendment |
| Stage 1 relevance | Ignored; lifecycle is sync at Stage 1 with no actor spawn |
| Stage 4 relevance | Live; consumed by `spawn_with_timeout` in §2.8.3's spawn graph |

V3.x revisits if real-world latency surfaces longer-than-5s
legitimate paths; the revisit changes defaults, not surface.

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

#### 2.8.7 Round 3 / Round 4a dispositions

- **The trait surface in §2 does not change for lifecycle
  concerns.** Lifecycle stays inherent on `Engine<S>`; the trait
  surface only sees the actors after they're alive. (Q9.11 closed
  no for `load_state()` on `PersistenceEngine`; lifecycle
  construction is the orchestrator's concern.)
- **§7's invariant scope is trait surfaces, not inherent methods
  (Round 4a clarification).** The "trait method signatures in §2
  do not change at Stage 4" invariant covers the traits in §§2.1
  through §2.7. Inherent methods on `Engine<S>` (the lifecycle
  constructors, `Engine::refresh`, etc.) are *not* covered by
  §7.1; their signatures may change at Stage 4 with explicit
  rationale and CHANGELOG documentation. The Stage 1 sync /
  Stage 4 async lifecycle divergence is one such case (per
  §2.8.3); `Engine::refresh` keeping its sync signature with
  internal `Handle::block_on` is another (per §4.2).
- **The spawn graph is part of the spec (§2.8.3); the landing
  graph is a separate concern (§8.1).** Both graphs are pinned;
  reviewers conflating them risk arguing for the wrong
  parallelism in either context.
- **Stage 4 lifecycle is async-public (Round 4a, reverses Round 3
  lean).** `Engine::create` and the `open_*` constructors return
  `impl Future<…>`; callers absorb `.await` at construction.
  Rationale per §2.8.3.
- **Default per-actor spawn timeout: 5 seconds.** Configurable via
  `EngineConfig`; documented as such in `Engine::create`'s
  rustdoc at Stage 4. `EngineConfig`'s shape and Stage 1 / Stage 4
  field-relevance are pinned in §2.8.8 below.
- **Drop semantics are best-effort at Stage 4; explicit
  `Engine::close` is required.** Pinned in §2.8.6.
- **Stage 1 destructor independence vs Stage 4 ordered teardown
  (Round 4a — Item 7 softening).** Round 3's "drop matches the
  teardown graph" framing conflated two distinct properties:
  Stage 1 destructors are *individually correct* without
  inter-field coordination, while Stage 4 actor stop cascades
  require *ordered teardown* via `Engine::close`'s explicit
  cascade. Field declaration order on `Engine<S>` is a
  type-parameter-ordering decision (per §3), not a Drop-order
  decision; the Stage 4 teardown graph (§2.8.5) is the
  load-bearing ordering. See §2.8.2 for the full softening.

#### 2.8.8 `EngineConfig` (Round 4a — Item 9 pin)

`EngineConfig` is the construction-time configuration struct
threaded through the lifecycle constructors and into actor spawn
at Stage 4. Round 4a pins its origin, lifetime, and Stage 1 /
Stage 4 field-relevance shift.

**Origin.** `EngineConfig` exists at Stage 1 with all fields
defined; lives in [`engine/config.rs`](../rust/shekyl-engine-core/src/engine/config.rs)
(new module, sibling to `engine/error.rs`). The struct is
`#[non_exhaustive]` so future fields (V3.1 multisig, V3.x
Component 3 adaptive-burn knobs) extend additively without
breaking V3.0 callers.

**Lifetime.** Constructed once by the binary entry point (or by
the test harness in `engine::test_support`); passed by value
into `Engine::create` / `Engine::open_*` constructors;
`Engine<S>` retains a clone for runtime reference. At Stage 4
each spawned actor receives the relevant subset of fields at
spawn time (Persistence gets the file-related fields; Daemon
gets the network-related fields; etc.).

**Stage 1 / Stage 4 field-relevance shift.** The struct shape is
the same across stages; the *relevance* of individual fields
shifts. At Stage 1, actor-specific fields (per-actor spawn
timeouts, mailbox sizes, supervisor-strategy hints) are unused —
construction is in-process and there are no actors to spawn.
Stage 1 implementations ignore those fields; tests can leave them
at defaults. At Stage 4, every field is live.

```rust
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct EngineConfig {
    // Used at all stages.
    pub network: Network,
    pub capability: Capability,
    pub wallet_file: PathBuf,
    pub daemon_url: String,

    // Stage-4-relevant; ignored at Stage 1.
    pub spawn_timeouts: SpawnTimeouts,
    // Future: mailbox sizes, supervisor strategy, observability hooks.
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct SpawnTimeouts {
    pub daemon: Duration,
    pub persistence: Duration,
    pub economics: Duration,
    pub key: Duration,
    pub ledger: Duration,
    pub refresh: Duration,
    pub pending_tx: Duration,
    // Future: stake (Phase 2b), archival (V3.x).
}

impl Default for SpawnTimeouts {
    fn default() -> Self {
        let d = Duration::from_secs(5);
        Self { daemon: d, persistence: d, economics: d, key: d,
               ledger: d, refresh: d, pending_tx: d }
    }
}

impl SpawnTimeouts {
    /// Builder-style override for the daemon spawn timeout.
    /// Same pattern (`with_<actor>`) for each field; lets callers
    /// override one timeout without specifying all of them.
    pub fn with_daemon(mut self, d: Duration) -> Self {
        self.daemon = d;
        self
    }
    // … with_persistence, with_economics, with_key, with_ledger,
    //     with_refresh, with_pending_tx
}
```

**Per-actor over uniform.** `SpawnTimeouts` carries one
`Duration` per actor rather than a single uniform timeout
because the actors have materially different legitimate latency
profiles. `PersistenceEngine`'s spawn cost includes
cold-cache disk I/O for an encrypted wallet file; `DaemonEngine`'s
spawn cost includes TLS handshake against a possibly-distant
peer; `KeyEngine`'s spawn cost includes Argon2id KDF — three
distinct latency distributions. A uniform timeout that fires
identically across all three loses diagnostic information at
the failure boundary ("which actor was slow?"). Per-actor
timeouts let the failure mode be specific. The
`#[non_exhaustive]` discipline plus builder-style overrides
preserves the per-actor specificity while letting callers
override individual fields ergonomically.

**`EngineConfig` lifetime revisability (V3.0 by-value;
revisable to `Arc` at V3.1+).** At V3.0 the struct is small
(network enum, capability enum, wallet_file path, daemon_url,
SpawnTimeouts); cloning is essentially free, and `Arc` would
add reference-counting overhead with ergonomic friction
(`config.daemon_url` becomes `(*config).daemon_url` or
`&config.daemon_url`). By-value is the V3.0 lean.

The decision is *revisable* at V3.1+ if `EngineConfig` grows
substantially — multisig parameters, archival policy, V3.x
adaptive-burn knobs, anonymity-network-coordination configs.
The transition is mechanical: change the field type from
`EngineConfig` to `Arc<EngineConfig>` in `Engine<S>` and at
actor spawn sites; callers continue to pass `EngineConfig`
because `Arc::new` construction is internal.

This pre-positions for the change without committing to it now.
Same pattern as the V3.0 unbounded-mailbox decision (revisit at
V3.x if backpressure surfaces). Pinning the revisability lets
future readers see the planned evolution rather than
re-deriving the decision when growth makes it necessary.

**Why a single struct rather than per-actor configs.** Per-actor
configs would require separate plumbing for each actor at the
constructor boundary, which (a) makes V3.0's Stage 1 / Stage 4
transition noisier (each new actor at Stage 4 adds a new
constructor parameter) and (b) makes test harness construction
more verbose. A single `EngineConfig` keeps the surface small;
fields' relevance is documented per-field; actors at Stage 4
extract the slice they need at spawn time.

**Why `#[non_exhaustive]`.** V3.1 multisig, V3.x adaptive-burn,
and V3.x anonymity-network-coordination will all want
construction-time parameters. `#[non_exhaustive]` lets V3.0 ship
a fixed shape that V3.1+ extends without consumer-side breakage.

**Test-harness construction.** `EngineConfig::test_default()`
(in `#[cfg(test)] pub(crate)`) returns a config with safe
test-friendly defaults: `Network::Testnet`, in-memory daemon URL
stub, ephemeral wallet path, and `SpawnTimeouts::default()`.
Tests that need to override specific fields use
`EngineConfig { … ..EngineConfig::test_default() }` struct-update
syntax.

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
`engine.keys.sign_transaction(…)` could in principle run
concurrently — they share no state — but Stage 1's outer lock
serializes them anyway. The over-serialization is invisible to
correctness; it just leaves performance on the table.

**Stage 1 interior-mutability measurement gate (Round 4a —
Item 14).** Per the §2 sweep, Stage 1 implementing types use
interior mutability (`RwLock<LedgerState>`,
`Mutex<ReservationTracker>`, `Mutex<WalletFileState>`) so the
trait methods can be `&self`. Under the outer
`Arc<RwLock<Engine>>` lock at Stage 1 these inner locks are
*redundant* — the outer lock has already serialized access —
but they are paid for on every read-path call. The "redundant"
characterization is structurally correct but **the cost is
unmeasured**, and the spec does not get to claim the cost is
acceptable without evidence.

The gate has three pinned components:

1. **Measurement requirement.** Before any Stage 1
   implementation PR is merged to `dev`, read-path overhead is
   measured against the existing baseline using `criterion`
   and `iai-callgrind`.
   *The baseline is per-bench and frozen at each bench's
   introducing-PR merge SHA: `engine_trait_bench_ledger_synced_height`
   is frozen at Stage 0 PR-2's merge SHA (the harness PR); each
   deferred bench is frozen at the merge SHA of the per-trait PR
   that introduces it (refined in Stage 0 PR-B; see
   [`docs/design/STAGE_0_HARNESS.md`](design/STAGE_0_HARNESS.md)
   §4.5 for the per-bench operationalization).*
   PR-specific deltas are measured against each bench's frozen
   reference, not against an earlier or later commit; a bench's
   frozen baseline is re-captured only if a non-Stage-1 change
   materially shifts that bench's hot-path cost (in which case
   the re-capture is itself a baseline-bumping commit, named in
   `PERFORMANCE_BASELINE.md` and announced in PR review).
   *Per-PR delta tracking across the Stage 1 series (Round 5 —
   Item 2; refined in Stage 0 PR-B):* each Stage 1 PR's
   description carries one cumulative-delta line per bench
   currently in scope at that PR, each computed against that
   bench's specific frozen-baseline SHA. The cumulative delta
   for a given bench is the sum of per-PR deltas accumulated
   from that bench's introducing SHA through the current PR;
   each bench's cumulative delta is independent (cumulative
   deltas do not sum across benches). Reviewers consult
   per-bench cumulative deltas during review; the frozen
   baseline numbers themselves are not re-measured until
   Stage 1 closes. At Stage 1's end (when the last per-trait PR
   merges) the "redundant against outer lock" cost becomes the
   new normal, and re-baselining for Stage 2/3/4 work is a
   separate decision tracked at that boundary, not by this
   gate. The hot paths under measurement are at minimum
   `KeyEngine::account_public_address`,
   `LedgerEngine::balance`, `LedgerEngine::synced_height`,
   `EconomicsEngine::current_emission`, and
   `EconomicsEngine::parameters_snapshot`. Additional paths
   are measured if reviewer judgment identifies them as
   hot-path during PR review (UI render-loop callers,
   high-frequency API surfaces).
2. **Documentation requirement.** Measurements land in
   `docs/PERFORMANCE_BASELINE.md` (new at Round 4a) before
   Stage 1 PR review begins. The document names the
   measurement methodology (`criterion` configuration,
   sampling discipline, host conditions), the baseline
   numbers, the post-interior-lock numbers, and the percentage
   delta per path. Reviewers cite the document during Stage 1
   PR review.
3. **Threshold of concern.** Two thresholds, calibrated to
   typical `criterion` noise floor (1–3% under good
   conditions) and to the cost realities of hot-path overhead:
   - **>10% on any hot path** requires explicit justification
     in the PR description naming the source of overhead and
     why the cost is acceptable (e.g., "the additional
     critical section is amortized across the operation's
     larger work; the relative overhead at the operation's
     full cost is <2%"). PR review may accept the justification
     or send the PR back for optimization.
   - **>25% on any hot path** requires optimization before
     merge; the gate is binding, not advisory.

Below 10%, the cost is accepted and the documented numbers
land in `CHANGELOG.md` alongside the Stage 1 cutover.

**Candidate optimizations for the revisit case.** If the
threshold is exceeded, the response space is constrained
(rather than open-ended) to keep the revisit actionable:

- **Narrowing critical sections** — restructuring the
  implementing type so the inner lock guards only the
  mutation-prone subset of state, with cached read-only
  values exposed via `&self` methods that don't acquire the
  lock at all.
- **`parking_lot::RwLock` substitution** — `parking_lot`'s
  read lock is materially cheaper than `std::sync::RwLock`
  under uncontended conditions (the V3.0 case under the
  outer lock); the substitution is a one-line change at the
  Stage 1 implementing-type level.
- **`Arc`-published snapshots for cached read-only values** —
  values that are stable across a logical operation (e.g.,
  `synced_height` between scan ticks, the `AccountPublicAddress`
  for the engine's lifetime) move to `Arc<T>` published once
  and read lock-free thereafter. The same pattern as the §3.3.6
  `EconomicsParametersSnapshot` mailbox-bypass at Stage 4,
  applied earlier to Stage 1 hot paths.

The choice depends on the specific overhead source identified
by the benchmark; the spec does not pre-commit to a specific
optimization, only to the candidate set.

The gate's relationship to Path B: Path B's per-actor mailbox
cutover removes the outer lock entirely, so Stage 4 has *no*
redundant interior-mutability cost. The Stage 1 gate exists
because Path B is months away and the redundant cost is paid
in the interim. The spec acknowledging the cost is unmeasured
is the difference between a documented assumption and an
implicit assertion.

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
// Stale-snapshot persistence: the snapshot is captured at
// argument-evaluation time, *before* either join! arm runs.
// At Stage 1 the outer RwLock makes the apply complete before
// save_state runs anyway (the lock acquire serializes the arms),
// so the saved snapshot is post-apply by accident. At Stage 4
// no such serialization exists; save_state persists the
// pre-apply snapshot it was handed and the arms do overlap.
let (apply_result, persist_result) = tokio::join!(
    engine.ledger.apply_scan_result(scan),
    engine.persist.save_state(&engine.ledger.snapshot()),
);
```

The unsafety is **stale-snapshot persistence**, not a race
condition in the conventional sense. `tokio::join!`'s arms
start polling eagerly, but the inner `engine.ledger.snapshot()`
*expression* is evaluated at argument-construction time — once,
before either arm runs. So the snapshot value passed to
`save_state` is whatever the ledger held at the moment the
`tokio::join!` macro expanded its arguments, and at Stage 4
that's *before* the apply has had a chance to run. The persist
arm dutifully writes the pre-apply snapshot to disk; the apply
arm then mutates the ledger; the on-disk state is now older
than the in-memory state by exactly one apply.

At Stage 1 the bug is hidden: the outer `RwLock` serializes the
two arms (one acquires the write lock, the other waits), so by
the time `save_state` runs, the snapshot it was handed has been
*overwritten* — both arms touch the same lock guard, and the
last-writer-wins ordering happens to land post-apply state into
the saved file. This is *accidental correctness*: the lock
prevents the bug by accident, not by design.

At Stage 4 the accidental correctness disappears: separate
mailboxes, separate channels, no cross-actor lock to enforce
the serialization. The persist arm proceeds with the captured
pre-apply snapshot, and the on-disk state diverges from the
in-memory state silently. There is no panic, no error, no log
line — just a subtle persistence-staleness bug that surfaces
as "wallet state on disk lags one apply behind in-memory state
under some conditions."

The lesson is twofold:

1. *`tokio::join!` evaluates argument expressions before
   polling arms.* Cross-trait reads embedded in a join arm's
   argument are captured at expansion time, not at arm-run
   time — independent of any lock or actor boundary.
2. *Stage 4 removes the accidental serialization* that an
   outer Stage-1 lock provides. A pattern that "happens to
   work" at Stage 1 because the lock structure makes it work
   may break silently at Stage 4 because the lock structure
   is gone.

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
let (fee_estimates, signatures) = tokio::join!(
    engine.daemon.get_fee_estimates(),
    engine.keys.sign_transaction(&tx),
);
```

`get_fee_estimates` and `sign_transaction` target different traits
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
are independent (like the `fee_estimates` + `sign_transaction`
example).

This is a code-review checklist item, not a lint. Lighter than
tooling, heavier than vibes. Reviewers reading PRs that touch
trait orchestration apply this check; PR descriptions that don't
address it are sent back for amendment.

#### 3.3.6 EconomicsEngine reads at Stage 4 (Round 4a Resolution C)

`EconomicsEngine` reads (`current_emission`, `burn_fraction`,
`pool_weighted_total`, `parameters_snapshot`) are pure-function
or pure-snapshot at V3.0. The trait surface in §2.7 returns the
**value type** `EconomicsParametersSnapshot` (no `Arc` in the
trait return); the implementation choice of how to make that
return cheap is a Stage 4 implementation detail that does not
leak into the trait.

This matches the §4.1 `LedgerSnapshot` pattern: the `Snapshot`
type is `Clone` with cheap-clone semantics (it contains owned
small fields directly, and any large state is held behind
internal `Arc`s within the struct definition). At Stage 4 the
`EconomicsActor` publishes an `Arc<EconomicsParametersSnapshot>`
internally and serves `parameters_snapshot()` requests by
returning a clone of the inner value (which is itself cheap
because the struct's large state is `Arc`-wrapped); callers
receive a value-typed `EconomicsParametersSnapshot` and work
against it without mailbox round-trips for repeated reads.

The Round 3 §3.3.6 wording leaked `Arc<EconomicsParametersSnapshot>`
into caller-visible territory; Round 4a corrects this so the
trait surface expresses *what the operation does* (return a
snapshot) rather than *how the implementation optimizes shared
access* (return an `Arc`). Trait surfaces don't leak storage
decisions; the LedgerSnapshot pattern is preserved verbatim for
EconomicsParametersSnapshot.

**Deliberate "value type with implementation flexibility"
pattern.** The trait surface returning a value-typed
`EconomicsParametersSnapshot` accommodates two implementations
with materially different storage strategies, both satisfying
the same contract:

- **Stage 1 `LocalEconomics`** returns a snapshot whose internal
  representation has *no* `Arc`s — the struct holds owned small
  fields directly, because the state is constants-derived and
  small. Cheap-clone is "memcpy of a few fields"; no
  reference-counting overhead.
- **Stage 4 `EconomicsActor`** returns a snapshot whose internal
  representation *does* hold `Arc`s for any large state
  (parameter blob, observation history at V3.x), because the
  state is published once and read many times via mailbox-bypass.
  Cheap-clone is "Arc::clone"; reference-counting overhead is
  amortized across the bypass benefit.

This is a *deliberate* design pattern, not an accident of the
trait surface. The trait expresses the contract (a snapshot is
returned, cheaply, of stable type); the implementation chooses
the storage strategy that fits its access pattern. Future
trait surfaces that return cheap-clone value types follow the
same pattern — `LedgerSnapshot` already does, and Phase 2b's
`StakeEngine` snapshot returns will too.

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
  (per §7's five-checkpoint discipline).
- **Operations whose side effects are idempotent or whose
  post-drop continuation is acceptable** can rely on drop
  semantics. `KeyEngine::sign_transaction` is acceptable to drop —
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

- **Class a** is most read-style methods: `balance`,
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

#### 3.4.4 Long-running operation cancellation pattern (Round 4b — Item 16)

Long-running operations — currently `RefreshEngine::produce_scan_result`,
prospectively V3.x's FCMP++ proof generation per §10.4.2 — fall
in §3.4.3's class c. The pattern for class-c methods extends the
async signature with two independent channels:

```rust
async fn long_running_op(
    &self,
    inputs: Inputs,
    cancel: CancellationToken,
    progress: Option<mpsc::Sender<Progress>>,
) -> Result<Output, EngineError>;
```

`cancel` is the caller's signal to abandon work. The implementor
checks `cancel.is_cancelled()` at controlled checkpoints (per
§7's five-checkpoint discipline) and returns a cancellation-shaped
error — `EngineError::Cancelled` or trait-specific equivalent —
not a partial result. The cancellation error is structurally
distinct from `RuntimeFailure` per §5.1: cancellation is a
caller-driven, expected outcome; `RuntimeFailure` is an actor
crash. Callers handling `Result` distinguish the two for §5.2's
retry contract.

`progress` is the operation's visibility channel (per §3.5). When
`None`, the implementor skips progress emission; when `Some`, the
implementor sends progress events at the same checkpoints where
it checks `cancel`. `progress.send` returning `Err` (the receiver
was dropped) is treated as "no listener, continue silently" — *not*
as cancellation. Conflating progress-receiver-dropped with cancel
re-introduces the talking-stick smell §1.4 rejects: the
implementor would have to peek at the progress channel's state to
infer caller intent, which is the shape that breaks at Stage 4
actor boundaries. Cancel and progress are independent values
flowing through the method signature, not implicit hooks coupled
through their failure modes.

**Drop interaction** (per §3.4.2): dropping the awaited future is
observation-only at Stage 4 — the message is already in the
actor's mailbox; the actor will run the operation to completion
even though the reply is discarded. To cancel observably at
Stage 4, the caller signals `cancel` *before* dropping the
future. At Stage 1 the future-drop additionally aborts the task,
so dropping is sufficient to cancel — but Stage-4-ready code
signals `cancel` regardless, because the trait surface is
identical at both stages and the discipline that survives Stage 4
also works at Stage 1.

The pattern preserves §1.4's actor-shape discipline at Stage 4:
`cancel` maps to a tell-style mailbox message that sets a flag
the actor checks at checkpoints; `progress` maps to an `mpsc`
forwarded from the actor to the caller. The trait surface is
unchanged across the cutover; the implementation behind it shifts
from in-process awaits to actor-mailbox tells, transparently.

**Progress-channel backpressure (Round 5 — Item 3).** Progress
channels follow the same unbounded-by-default pattern as Stage 4
actor mailboxes (§3.3.2) and the bounded-mailbox-trigger
threshold framework (§10.4.3): unbounded `mpsc::Sender<Progress>`
at V3.0; the implementor sends progress events without
backpressure-blocking; receiver-dropped is observed via
`progress.send` returning `Err`, treated per the paragraph above
as "no listener, continue silently"; and the long-running
operation itself never blocks on progress emission because the
channel cannot fill. Bounded progress channels — which would
introduce a third blocking surface alongside `cancel` and the
operation's own work — are deferred to V3.x under the *same*
trigger conditions as §10.4.3: production observation of
pathological progress-channel accumulation (UI receivers
chronically slow relative to producer cadence), plus a
security-posture review confirming the unbounded channel has not
become an OOM surface in practice. Until either trigger fires,
the unbounded channel is the contract; implementors do not
"defensively" add a bounded variant. The §10.4.3 framework
governs both axes uniformly so the discipline of "channel
boundedness is evidence-gated, not preemptive" applies to the
mailbox surface and the progress surface in lockstep.

#### 3.4.5 Round 3 dispositions

- **Drop-cancellation is the default contract** for async trait
  methods (per §3.4.1). Implementors document deviations.
- **Stage 4 drop is observation-only**, not cancellation, for
  Class b methods (per §3.4.2). Operations that must not
  side-effect on drop use in-band cancellation tokens.
- **Three-class framework** (a / b / c) is pinned (per §3.4.3);
  the per-method classification table is a Round 4 fill-in.
- **Class-c long-running pattern** (per §3.4.4) extends the
  framework with the cancel + progress dual-channel signature.

### 3.5 Observability: tracing at call sites, not on trait surfaces (Round 4a — Item 18)

**Observability is provided via the `tracing` crate at call
sites; trait methods do not expose metrics or introspection on
their surfaces.** This is intentional and rejects a class of
"add observability hooks to traits" proposals before they
recur.

The argument for trait-level observability hooks runs: opaque
incentive systems breed centralization and attacks; therefore
the wallet should expose introspection on its incentive-relevant
state via methods like `KeyEngine::metrics()`,
`LedgerEngine::stats()`, `EconomicsEngine::observability_snapshot()`.
The argument is mis-scoped to the wallet trait spec for two
reasons:

1. **The wallet's observability of its own state is already
   adequate.** `LedgerEngine::balance` exposes how much this
   wallet has; `EconomicsEngine::parameters_snapshot` exposes
   the currently-observable economic state; the wallet's
   persistent ledger surfaces per-transaction history through the
   `LedgerBlock::transfers` slice accessor that wallet-internal
   callers consume directly (see §2.2's 2026-05-03 transfer-clone
   discipline amendment for why this is not a trait-level method
   at Stage 1). A user can already see
   what's happening to their own funds. The proposed
   observability hooks are about *network-wide* visibility
   (staking centralization patterns, MEV extraction, fee
   distribution) — and that's not wallet observability, it's
   chain observability. The wallet can fetch chain-wide
   metrics via daemon RPC consumed through `DaemonEngine` if
   needed, but the trait spec should not pin it because it's
   not a wallet-engine concern.
2. **Trait-level observability invites scope drift.** Once
   `KeyEngine` has `metrics()`, future contributors propose
   `LedgerEngine::metrics()`, `RefreshEngine::metrics()`, etc.
   Each addition is justified individually; collectively they
   expand the trait surface in ways the §1.4 actor-shape
   discipline cannot easily evaluate (a `metrics()` method
   that returns "how busy was this actor" is implicitly
   per-entity-state cross-cutting an entity selector that the
   trait does not own — the same drift class clause (d) of
   §2.7's discipline test rejects).

**The right pattern is `tracing` spans at call sites.**
Operations get spans (`#[instrument]` on the inherent
`Engine<S>` method, or explicit `tracing::info_span!` at the
call site); spans carry context (operation name, key
parameters, duration); observers consume spans externally via
subscribers (file logging, OpenTelemetry exporter, a future
in-process metrics sink). This is the established Rust
pattern, it doesn't require trait-level observability hooks,
and it composes orthogonally with the §1.4 discipline because
it's cross-cutting via attribute, not via method surface.

**Stage 4 actor instrumentation** uses the same pattern:
`kameo` actors are instrumented at the message-handler level,
not the trait-method level. Spans wrap the message receive,
capture the message variant, and propagate to any nested
operations the handler invokes. This gives Stage 4 the same
observability shape as Stage 1 (call-site spans) without
trait-surface changes.

The economic-design observability that DESIGN_CONCEPTS.md
references — visibility into release-multiplier behavior,
adaptive-burn parameter trajectories, stake-tier distribution
— lives at the chain layer (consumed via `DaemonEngine` RPC)
and at the design-document layer (DESIGN_CONCEPTS.md itself
documents the parameters and their dynamics). The trait spec
does not extend into either layer. See §1.5's scope-guard
meta-pattern for the broader discipline this rejection
participates in.

**Long-running operations (Round 4b — Item 8 carry-forward).**
The natural counter-question to this rejection is: what about
operations that genuinely take long enough to need progress
reporting? The canonical V3.x case is `KeyEngine::sign_transaction`
if FCMP++ proof generation becomes user-perceptible at scale (the
target sub-second per single-output proof is revisable on
benchmark data per §10.4.2). The answer is: **long-running trait
operations use in-band progress channels per the §2.3
`RefreshEngine::produce_scan_result` pattern, not trait-level
observability hooks.** Progress reporting becomes an explicit
method parameter (a `mpsc::Sender<Progress>` or equivalent
channel) alongside the existing `CancellationToken` parameter;
the channel sends progress updates that the caller drains and
exposes to the UI. This pattern preserves the §1.4 actor-shape
discipline because progress reporting is an explicit value
flowing through the method signature, not an implicit hook on
the trait surface. §3.4.4's long-running-operation cancellation
pattern (Round 4b — Item 16) covers the cancellation half of
the same shape; the two together specify how a long-running
trait method is structured — `cancel` for caller-driven
abandonment, `progress` for operation-driven visibility, both
explicit in the signature.

---

## 4. Async story

The table below replaces the Round 1/2 sync-vs-async split with a
fuller per-method view. Round 3 adds the **Idempotency** column;
Round 4b adds the **Cancel class** column (a / b / c per
§3.4.3). Sync methods do not carry a cancel class because they
cannot be cancelled mid-call — they're listed as `n/a`.

Cancel classes (§3.4.3 recap): **a** = side-effect-free (drop is
cancel-equivalent at all stages); **b** = side-effect-eventual
(drop at Stage 1 is cancel-equivalent because the work happens
in the caller's task; drop at Stage 4 is *observation-only*
because the actor's mailbox already received the message and
the handler may complete asynchronously); **c** = explicitly
token-cancellable via `CancellationToken` parameter (drop is
not the cancellation surface; the token is).

| Trait | Method | Async/Sync | Idempotent? | Cancel class |
|---|---|---|---|---|
| `KeyEngine` | `account_public_address` | sync | yes (read-only) | n/a |
| `KeyEngine` | `derive_subaddress` | sync | yes (deterministic in `(view_secret, subaddress_index, purpose)`; pure derivation) | n/a |
| `KeyEngine` | `try_claim_output` | async | **conditionally** — `NotMine` is fully idempotent; `Mine` re-binds the same `OutputHandle` deterministically under the M3b+ handle pathway (`handle = cSHAKE256(view_secret \|\| tx_hash \|\| output_index)`) | **b** (post-M3b workflow-internal handle-table insertion on `Mine`; deterministic handle so re-call observes the existing entry) |
| `KeyEngine` | `sign_transaction` | async | **implementation-defined per replay-rejection contract** (Pattern-6 cluster, [`STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md) §7.14) — committed direction is replay-rejection at handle resolution | **a** (no observable side effect outside the returned signature material; signing-then-not-using is invisible to others) |
| `LedgerEngine` | `synced_height` | sync | yes (read-only) | n/a |
| `LedgerEngine` | `snapshot` | sync | yes (read-only; returns owned snapshot) | n/a |
| `LedgerEngine` | `balance` | sync | yes (read-only) | n/a |
| `LedgerEngine` | `apply_scan_result` | async | **conditionally** — idempotent given the same `ScanResult` against the same starting `synced_height`; if the height has advanced (because a concurrent merge landed), the second apply returns `RefreshError::ConcurrentMutation` deterministically. Never produces a double-applied state. | **b** (mutates ledger state; Stage 4 drop after enqueue is observation-only — the merge may complete asynchronously) |
| `RefreshEngine` | `produce_scan_result` | async | no (each call observes the daemon's current tip; tip advances over time) | **c** (explicit `CancellationToken` parameter; five-checkpoint cancellation per §7) |
| `PendingTxEngine` | `build` | async | no (each build picks fresh decoys; reservation IDs are monotonic) | **b** (allocates a reservation and mutates the reservation tracker; Stage 4 drop after enqueue is observation-only) |
| `PendingTxEngine` | `submit` | async | **conditionally** — daemon dedupes by tx hash; calling `submit` twice on the same `ReservationId` produces one mempool submission | **b** (network side effect via `DaemonEngine`; Stage 4 drop after enqueue is observation-only) |
| `PendingTxEngine` | `discard` | async | yes (discarding an already-discarded reservation is a no-op error variant the caller can treat as success) | **b** (mutates reservation tracker) |
| `PendingTxEngine` | `outstanding` | sync | yes (read-only) | n/a |
| `DaemonEngine` | `get_fee_estimates` | async | yes (read-only; fee state is a snapshot at call time) | **a** (network read; no wallet-side side effect) |
| `DaemonEngine` | `submit_transaction` | async | **conditionally** — daemon dedupes by tx hash (same tx bytes → same submission outcome) | **b** (network side effect; daemon may receive and act on the transaction even if the wallet drops the await) |
| `DaemonEngine` | `Rpc` supertrait methods | async | per-method (inherits `Rpc`'s spec) | per-method (read-only RPCs are class **a**; mutating RPCs are class **b**) |
| `PersistenceEngine` | `base_path` | sync | yes (read-only; returns immutable cached path) | n/a |
| `PersistenceEngine` | `network` | sync | yes (read-only) | n/a |
| `PersistenceEngine` | `capability` | sync | yes (read-only) | n/a |
| `PersistenceEngine` | `save_state` | async | yes (last-write-wins; saving the same state twice yields the same final on-disk bytes) | **b** (writes file; Stage 4 drop after enqueue is observation-only) |
| `PersistenceEngine` | `save_prefs` | async | yes (last-write-wins) | **b** |
| `PersistenceEngine` | `rotate_password` | async | no (state changes per call; old credentials are no longer valid after a successful rotation) | **b** (writes file; Stage 4 drop is observation-only — rotation may complete after caller drops) |
| `EconomicsEngine` | `current_emission` | sync | yes (read-only; deterministic given height at V3.0; deterministic given height plus observed-activity state at V3.x — observable via `parameters_snapshot`) | n/a |
| `EconomicsEngine` | `burn_fraction` | sync | yes (read-only; deterministic given inputs at V3.0; deterministic given inputs plus state at V3.x) | n/a |
| `EconomicsEngine` | `pool_weighted_total` | sync | yes (read-only; canonical derivation from current pool state) | n/a |
| `EconomicsEngine` | `parameters_snapshot` | sync | yes (read-only; returns owned snapshot) | n/a |

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
- `sign_transaction`: retry is **rejected at handle resolution**
  per the post-M3 replay-rejection contract — consumed handles
  are gone from the table, so a re-call against the same
  `TxToSign` fails handle resolution. Callers distinguish
  "broadcast succeeded but acknowledgment lost" (no retry;
  rebuild with replacement inputs) from "signing failed before
  any state change" (retry admissible against fresh handles).
- `produce_scan_result`, `PendingTxEngine::build`,
  `rotate_password`: retry is *semantically distinct* from the
  original call (different scan window, different reservation,
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

**`#[tokio::test]` test-attribute selection (Round 4b — Item 5).**
Tests that exercise `Engine::refresh` (or any sync surface that
reaches `Handle::block_on` against an async trait method) must
use `#[tokio::test(flavor = "multi_thread")]` rather than the
default `#[tokio::test]`. The bare `#[tokio::test]` attribute
creates a `RuntimeFlavor::CurrentThread` runtime by default,
which trips the same deadlock the production rustdoc warns
about: the test thread blocks on `Handle::block_on`, the
single-threaded runtime cannot make progress, and the test
hangs (often manifesting as a CI timeout rather than a clear
failure). The `flavor = "multi_thread"` argument creates a
multi-thread runtime with the default worker count, which
matches the production runtime requirement. Tests that
exclusively exercise async surfaces (no sync `Engine::refresh`
or analog) may use the default `#[tokio::test]` because
no `Handle::block_on` is invoked. The §6 test-boundary section
inherits this requirement: `MockDaemon`-driven `start_refresh`
integration tests are async-throughout and use the default
attribute; tests that drive sync `Engine::refresh` against
mocks use the multi-thread flavor explicitly.

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
converts to wire errors.

**`EconomicsError` (Round 4a — Item 5 pin).** New alongside
`EconomicsEngine` (§2.7); lives in the same `engine/error.rs`
module as the other per-trait error enums. V3.0 shape:

```rust
#[non_exhaustive]
pub enum EconomicsError {
    /// Stage 4 actor crash. Stage 1 implementations never produce
    /// this variant; `LocalEconomics` is pure-function over
    /// `shekyl-economics` constants and cannot crash in the
    /// actor sense.
    RuntimeFailure { actor: &'static str, reason: ActorCrashReason },
}
```

A single variant at V3.0; `#[non_exhaustive]` carries the
extension permission for V3.x's adaptive-burn observation
failure modes (e.g., observation-window-corruption) without
breaking V3.0 callers. Stage 1's `LocalEconomics` cannot
construct the variant — it's pure-function over
`shekyl-economics` constants and call-time inputs — so the
`Result<T, EconomicsError>` return type's `Err` arm is
unreachable at Stage 1 and trivially-handleable at Stage 4 where
the supervisor strategy of §5.1 is what produces the variant.

**Why `Result<T, Self::Error>` at V3.0 despite Stage 1
infallibility (load-bearing premise).** The `Result` ceremony in
the §2.7 trait method signatures exists for §7's
trait-surface-stability invariant: trait method signatures do
not change at Stage 4. A V3.0 surface that returned `T`
directly (because Stage 1 infallibility is structural) would
have to break the §7 invariant at Stage 4 cutover when
`RuntimeFailure` becomes constructible. The Result ceremony at
V3.0 is *Stage 4 surface stability paid forward*, not
defensive error handling against impossible failures. The §2.7
rustdoc on each method names this explicitly so future
contributors don't read `Result<T, EconomicsError>`, see
"V3.0 never returns Err," and write dead-code error-handling
branches; the correct V3.0 caller pattern is `?`-propagation,
not exhaustive `match` on the unreachable variant.

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

    /// Pending message drained during supervisor cascade;
    /// see §5.1's draining ordering discussion below.
    DrainedDuringSupervisorCascade,
}
```

**Per-trait error-enum enumeration (Round 4a — Item 10 pin).**
The seven trait-error families that gain the `RuntimeFailure`
variant at Stage 4 are explicitly:

| Trait | Error family | V3.0 origin |
|---|---|---|
| `KeyEngine` | `KeyError` | existing in `engine/error.rs` |
| `LedgerEngine` | `RefreshError` (shared with `RefreshEngine`) | existing |
| `RefreshEngine` | `RefreshError` | existing |
| `PendingTxEngine` | `PendingTxError` | existing |
| `DaemonEngine` | inherits per-method (e.g., `RpcError`); aggregated via `Send` / per-method paths | existing |
| `PersistenceEngine` | `IoError` (per §5's mapping) | existing |
| `EconomicsEngine` | `EconomicsError` | new in Round 4a (per Item 5 above) |

All seven enums are `#[non_exhaustive]` (where they aren't
already) and gain the `RuntimeFailure` variant alongside the
domain-specific variants they already carry. The variant is
*unreachable* at Stage 1 — Stage 1 implementations have no
actors and cannot construct it — but exists in the type so the
trait surface doesn't change at Stage 4 cutover. Per §5.1's
"Stage 1 implications" paragraph below, debug builds use
`debug_assert!(false)` in Stage 1 impls' error-construction
paths to catch any accidental construction.

**`RefreshError` is shared between `LedgerEngine` and
`RefreshEngine`.** This is intentional (per §2.2's Q9.5
disposition: `ConcurrentMutation` is the contract signal between
ledger and refresh, not a refresh-private error). The shared
family means a single `RuntimeFailure` variant on `RefreshError`
serves both traits; the `actor` field on the variant
distinguishes whether the failure originated in the ledger
actor or the refresh actor.

**Supervisor strategy: restart-and-fail-pending, no automatic
retry.** When an actor crashes mid-handler:

1. The pending message returns `RuntimeFailure { actor: …,
   reason: PanickedDuringHandler }` to its caller.
2. All other pending messages on the same actor's mailbox are
   drained and returned as `RuntimeFailure { reason:
   DrainedDuringSupervisorCascade }` to their respective callers
   — the supervisor does not re-deliver them after restart,
   because re-delivery would risk message-level non-idempotency
   cascading into observable double-effects.
3. The supervisor restarts the actor in a clean state.
4. New messages sent after the restart are processed normally.

**Draining ordering — observable contract (Round 4a — Item 11
pin).** When N pending messages are drained from a crashed
actor's mailbox, the order in which their callers observe the
`RuntimeFailure` return is **mailbox-FIFO**: the first message
to be drained corresponds to the next message that would have
been processed had the actor not crashed. Callers of multiple
pending messages on the same actor see returns in the same
order the messages were enqueued.

The crash-handler's own message is distinguished from the
drained messages by its `ActorCrashReason`:

- The message being processed when the crash happened returns
  `RuntimeFailure { reason: PanickedDuringHandler }`.
- All other pending messages return `RuntimeFailure { reason:
  DrainedDuringSupervisorCascade }`.

This lets a caller that sent N messages distinguish "messages
1..K-1 succeeded; message K was being processed when the crash
happened (and returns `PanickedDuringHandler`); messages K+1..N
were drained without being processed (and return
`DrainedDuringSupervisorCascade`)." The split-by-reason
disambiguation gives caller logic a concrete recovery surface:
the `PanickedDuringHandler` message *might* have side-effected;
the `DrainedDuringSupervisorCascade` messages definitely did
not.

**What "mailbox-FIFO observable" does not mean.** Two
clarifications:

- The supervisor does not guarantee ordering across
  *different* actors' drains during a multi-actor failure
  cascade. If KeyActor and LedgerActor both crash in the same
  scheduler tick, callers waiting on both see returns in
  interleaved order; no cross-actor ordering is contracted.
- The observable order is the order callers' awaited futures
  *resolve*, not the order the supervisor *processes* the
  drain. In practice these are the same under tokio's
  default scheduler, but a multi-thread runtime may interleave
  the resolutions across worker threads. Callers must not
  assume strict-real-time ordering of `await` returns.

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

**Restart budget — exhaustion converts recoverable to permanent
(Round 4b — Item 17).** Stage 4's `kameo` supervisor accepts a
per-actor restart budget: an upper bound on restarts within a
sliding window (e.g., "5 restarts in 60s"). Budget exhaustion
converts a recoverable failure into a permanent one — the
supervisor stops restarting the actor, the mailbox is closed,
and subsequent callers see `RuntimeFailure { reason: Permanent }`
exactly as they would for an actor declared non-recoverable at
spawn. The trait surface does not distinguish budget-exhaustion
from explicit non-recoverable strategy: `Permanent` is
`Permanent` either way, and callers branching on `RuntimeFailure`
need only the variant. Operationally, however, budget exhaustion
is a *signal* — the actor's panic source is recurrent, not
transient (a panic-loop driven by stuck input, a poisoned
invariant, an unforeseen runtime condition that returns
deterministically), and the operator's appropriate response is
manual intervention rather than re-construction-and-retry. The
budget value is a Stage 4 deployment parameter, not a
trait-surface concern; defaults and tuning live in the Stage 4
supervisor configuration documentation, alongside the
`SupervisorStrategy` choices. The property the spec pins is:
budget exhaustion is observable to callers as `Permanent`, never
silently swallowed; the operator-visible distinction (recurring
crashes vs first-time crash promoted to non-recoverable by
strategy choice) lives in operator-side observability, not in
the trait surface.

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

**Composition with §7's cancellation contract (Round 4a —
Item 16).** The `RuntimeFailure` path interacts cleanly with
§7's cancellation checkpoint contract. A crash during
`LedgerEngine::apply_scan_result` returns
`RuntimeFailure { reason: PanickedDuringHandler }` to the
orchestrator without completing the merge; the supervisor
restarts the actor in a clean state, which re-hydrates from
`PersistenceEngine` and resumes processing against the
post-restart (pre-merge) state. The orchestrator's pre-merge
checkpoint (per §7 invariant 4) is satisfied in this path
because no merge occurred, and the conditional-idempotency of
`apply_scan_result` (per §4) makes caller-driven retry safe.
The composition relies on three layered guarantees that all
exist already: §5.1's restart-and-fail-pending supervisor,
§4's idempotency column, and §7's checkpoint ownership split.
No structural addition is needed — only the composition's
explicit articulation here.

### 5.2 Caller retry contract for `RuntimeFailure` (Round 4b — Item 13)

§5.1 pins what `RuntimeFailure` *means* at the trait surface.
§5.2 pins what callers should *do* when they observe one — the
operational retry contract derived from §3.4.3's class framework
and §4's per-method idempotency column. Without this section,
callers either over-retry (re-issuing non-idempotent operations
and producing observable double-effects) or under-retry
(surfacing recoverable failures as user-facing errors when retry
would have succeeded). §5.2 closes the gap by mapping each
{class, idempotency, `RuntimeFailure` reason} triple to a
specific caller action.

**Class-a methods (read-style, no side effect).** Retry is
trivially safe: multiple invocations produce identical observable
behavior. Callers retry without consulting the idempotency column.
Examples: `LedgerEngine::balance`, `LedgerEngine::synced_height`,
`KeyEngine::account_public_address`,
`EconomicsEngine::current_emission`,
`EconomicsEngine::parameters_snapshot`. The class-a contract is
"retry until success or `Permanent`."

**Class-b methods (mutating, drop-observation-only at Stage 4).**
Retry safety depends on the §4 idempotency entry and the §5.1
`ActorCrashReason`:

| Caller observes | §4 idempotency | Retry action |
|---|---|---|
| `PanickedDuringHandler` | yes | retry against post-restart actor |
| `PanickedDuringHandler` | conditionally | check the §4-named condition; retry if held, surface otherwise |
| `PanickedDuringHandler` | no | surface to user; operation may have side-effected externally |
| `DrainedDuringSupervisorCascade` | any | retry; the operation definitely did not side-effect |
| `Permanent` | any | surface to user with operator-action prompt; engine must be reconstructed |

The split between `PanickedDuringHandler` and
`DrainedDuringSupervisorCascade` (per §5.1's draining ordering)
gives callers actionable distinction: drained messages definitely
did not run, so retry is safe regardless of idempotency; the
panicked message *might* have side-effected, so retry safety
follows §4's classification. The split is what makes the table's
"any" entries safe: drained messages don't depend on idempotency
because the operation never executed.

**Class-c methods (in-band cancellable).** Two error variants
distinguish caller-driven cancellation from actor-driven failure:

- `EngineError::Cancelled` (per §3.4.4) is the caller's expected
  outcome from signaling `cancel`. Retry semantics don't apply —
  the caller signaled cancel; the operation returned the
  cancellation-shaped error; there is nothing to retry. Callers
  handling `Result` distinguish `Cancelled` from `RuntimeFailure`
  for exactly this reason.
- `RuntimeFailure { … }` returned from a class-c method follows
  the class-b retry contract (the table above): the actor
  crashed; the cancel signal is irrelevant to the retry decision;
  idempotency and the `ActorCrashReason` determine the action.

**Layered-call relationships compose through idempotency
conditions.** Some trait methods call other trait methods
internally. The outer method's retry contract derives from the
inner method's idempotency: when both methods share an
idempotency property (e.g., a shared dedup key), the outer
method inherits the inner's safety, and callers can retry the
outer without knowing which layer crashed.

The clearest example today is `PendingTxEngine::submit` and
`DaemonEngine::submit_transaction`. The layered call:

- `PendingTxEngine::submit` looks up a reservation's transaction
  bytes from local state, constructs the submission payload,
  calls `DaemonEngine::submit_transaction` to submit to the
  daemon's mempool, and post-processes the daemon's response
  (marks the reservation submitted, records the tx hash).
- `DaemonEngine::submit_transaction` posts the transaction to
  the daemon's RPC; the daemon dedupes by tx hash on receipt —
  submitting the same tx twice produces a single on-chain
  effect because the daemon recognizes the duplicate and
  returns its existing-pool acknowledgment.
- §4 marks both methods as "conditionally idempotent (daemon
  dedupes by tx hash)" — the *same condition* applies at both
  layers because the layering is transparent to the dedup
  property.

Three crash cases under retry, summarized at a glance and then
walked individually below:

| Crash point | Inner (daemon) state at crash | Outer (post-processing) state at crash | Retry behavior |
|---|---|---|---|
| Before inner call | unsubmitted | not started | first daemon call; clean post-processing |
| After inner returned | submitted | partial / not started | dedup ack; post-processing applies |
| Mid-RPC inside inner | indeterminate (network race) | not started | dedup or first submit; post-processing applies |

1. **`PendingTxEngine::submit`'s actor crashed *before* calling
   `DaemonEngine::submit_transaction`.** The daemon never
   received the tx. Retry calls into the post-restart actor,
   which calls the daemon for the first time. Net: single
   submission.
2. **`PendingTxEngine::submit`'s actor crashed *after* the
   inner daemon call returned successfully but before
   post-processing completed.** The daemon already has the tx;
   the local reservation state may or may not be marked
   submitted. Retry calls the daemon again; the daemon's dedup
   recognizes the tx hash and returns its existing-pool ack;
   the retry's post-processing completes. Net: single
   submission, post-processing applied exactly once after the
   retry succeeds.
3. **`DaemonEngine::submit_transaction`'s actor crashed
   mid-RPC.** The daemon may or may not have received the tx
   (network race). Retry hits the daemon; if the original had
   reached mempool, the retry hits dedup; if not, the retry
   submits for the first time. Net: single submission either
   way.

In all three cases, the layered idempotency (`daemon dedupes by
tx hash`) produces a single observable submission. The condition
is layered: `PendingTxEngine::submit`'s safety derives from
`DaemonEngine::submit_transaction`'s safety, which derives from
the daemon's hash-dedup property. **Callers consulting §5.2 do
not need to know which layer crashed** — they retry the outer
method, and the layered idempotency makes the retry safe under
all three failure modes. This is the operational value of the
cross-method pinning: callers reason about the trait surface's
documented condition, not about per-layer failure modes.

**Layered errors preserve the inner `RuntimeFailure` verbatim
(Round 5 — Item 4).** Although the retry decision does not require
knowing *which* layer crashed, callers that *do* care — for
diagnostics, logging, alerting, or operator-action prompts —
need a structured way to identify the innermost failing actor
without private API access into the outer trait. The discipline
is **verbatim preservation**: when an outer trait method
propagates a `RuntimeFailure` from an inner trait method, the
outer return value carries the inner trait's error variant
*unchanged*, with `actor` naming the *innermost* failing actor
rather than a wrapping outer actor. The natural carrier is
§5.1's `EngineError` aggregate: `EngineError::Daemon(daemon_err)`,
`EngineError::Persistence(persistence_err)`, etc. — a typed
distinction that pre-empts the wrapping pattern.

The wrapping pattern (e.g., a hypothetical
`PendingTxError::DaemonFailed { reason: String }` variant that
flattens the inner `ActorCrashReason` into a string) is rejected:
flattening destroys the structured `ActorCrashReason` that the
§5.2 retry table consults, and forces callers to string-parse to
recover retry semantics. Verbatim preservation keeps the §5.1
type structure intact across layer boundaries, so the §5.2 retry
contract continues to hold mechanically — the
`PanickedDuringHandler` / `DrainedDuringSupervisorCascade` /
`Permanent` distinction remains a typed value the table rows can
match on, regardless of which layer originated the failure.

This rule has a structural consequence for outer error types:
they must be able to express any inner-trait `RuntimeFailure`
variant they propagate. `EngineError`'s `#[non_exhaustive]`
aggregate (per §5.1) makes this expressible without forcing each
outer trait to enumerate every possible inner failure source in
its own error type — outer methods that propagate inner failures
return the `EngineError` aggregate, and consumers downcast or
match as needed. Reviewers checking new layered methods confirm
that propagation uses the aggregate (or a similarly structured
inner-preserving carrier) rather than a flattening variant.

The pattern is general. Any trait method that calls another
trait method internally derives its retry contract from the
inner method's idempotency. Idempotency conditions compose
through layering: when an outer method's retry safety depends
on an inner method's idempotency, both `RuntimeFailure` paths
(outer crash before inner call; outer crash after inner call) are
covered by the inner method's condition. Reviewers checking new
trait methods that call other trait methods confirm the
layered-condition holds; if it doesn't, the outer method needs
its own dedup mechanism rather than inheriting the inner's.

---

## 6. Test boundary

The trait abstractions unlock a category of test that is not
possible today: a **fully-mocked `Engine<SoloSigner, MockKey,
MockLedger, MockDaemon, …>`** that drives `start_refresh`
end-to-end with deterministic chain state, deterministic key
material, and no filesystem.

> **(Post-M3 + Post-PR-4 note: substrate evolved away from
> full-Mock-X composition.)** The "fully-mocked
> `Engine<SoloSigner, MockKey, MockLedger, MockDaemon, …>`"
> framing above describes the Stage 1 design-time target. The
> shipped V3.0 substrate is hybrid:
>
> - **PR 3** (`STAGE_1_PR_3_KEY_ENGINE.md` §6.4) shipped without
>   a `MockKey` type. The no-Mock-X substrate uses a real
>   `LocalKeys` (the production `KeyEngine` implementor) seeded
>   with deterministic test input rather than a parallel
>   `MockKey` honoring `KeyEngine`'s contract.
> - **PR 4** retired `MockLedger` in favor of
>   `FaultInjecting<LocalLedger>` (C6β = `e94526dec`) and
>   retired `MockRefresh` in favor of `FaultInjecting<LocalRefresh>`
>   (C6α = `e9310542a`). The wrapper-based fault-injection
>   substrate composes a real production implementor with a
>   trait-boundary failure-injection wrapper (per the same
>   `RefreshEngine` / `LedgerEngine` trait bounds the
>   orchestrator already dispatches against), eliminating the
>   parallel-Mock-X contract-fidelity burden for these two
>   traits.
>
> The surviving Mock-X types as of PR 4 land:
> `MockDaemon`, `MockEconomics`, `MockPersistence`,
> `MockPendingTx`. The contract-fidelity discipline (§6.1
> Round-4b — Item 3) applies unchanged to those types AND to
> `FaultInjecting<...>` wrappers (which honor the trait
> contract by delegating to the wrapped production type's
> implementation).

Today's test coverage:

- **Producer-only:** `MockDaemon` in [`engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs)
  drives `produce_scan_result` directly. Twelve producer tests
  cover the linear-scan / reorg / RPC-failure / cancellation paths.
- **Driver-only with partial mocking:** the driver-side tests in
  `engine/refresh.rs` build a real `Engine<SoloSigner>` against an
  unreachable `SimpleRequestRpc` URL and assert error-path
  behavior. Stage 1 PR 1 (`DaemonEngine`) closes the
  end-to-end-against-synthetic-chain gap that previously existed:
  with `MockDaemon: DaemonEngine` and `Engine<S, D: DaemonEngine =
  DaemonClient>`, the existing chain-injection harness
  (`replace_chain_from`, `queue_height_error`, `queue_block_error`)
  is now available to `start_refresh` integration tests directly,
  via the `#[cfg(test)] pub(crate) Engine::replace_daemon` helper
  that swaps the daemon component on a real-engine fixture
  post-construction. The first hybrid test under
  `start_refresh_integration_tests::hybrid_linear_scan_5_blocks_advances_synced_height`
  exercises this path end-to-end.
`MockKey` and `MockPersistence` in particular let tests skip the
`AllKeysBlob` rederivation cost and the file-open advisory-lock
ceremony, which today add ~50–200 ms per test.

### 6.1 Pinned commitments for Stage 1

- Each trait gets a `Mock*` implementor in `engine::test_support`
  (`#[cfg(test)] pub(crate)`). The list as of Round 3:
  `MockKey`, `MockLedger`, `MockEconomics`, `MockDaemon`,
  `MockPersistence`, `MockRefresh`, `MockPendingTx`.
  - **(Post-M3 + Post-PR-4 update to the Round-3 list.)** Of
    the seven Round-3 commitments, three retired in favor of
    real-implementor + wrapper substrates: `MockKey` retired
    in PR 3 (`STAGE_1_PR_3_KEY_ENGINE.md` §6.4 no-Mock
    substrate; `LocalKeys` is used directly with deterministic
    test seeds); `MockLedger` retired in PR 4 (C6β =
    `e94526dec`; replaced by `FaultInjecting<LocalLedger>` +
    `LocalLedger::from_test_blocks(Vec<Block>)`);
    `MockRefresh` retired in PR 4 (C6α = `e9310542a`;
    replaced by `FaultInjecting<LocalRefresh>` +
    `Engine::replace_refresh` test-only setter). The
    surviving Round-3 commitments (`MockEconomics`,
    `MockDaemon`, `MockPersistence`, `MockPendingTx`) remain
    on the trait-boundary Mock-X pattern; the contract-
    fidelity discipline below applies to them and to the
    `FaultInjecting<...>` wrappers (which honor the trait
    contract by delegating to the real production
    implementor).
- `start_refresh` integration tests against a fully-mocked engine
  ship in the same Stage 1 commit that lands the trait surfaces.
- `MockEconomics` is constants-driven: the V3.0
  `LocalEconomics`-equivalent test double returns
  caller-configured emission / burn-fraction / pool-total /
  parameter-snapshot values. This isolates economics-consuming
  test scenarios (Phase 2b `StakeEngine` precursor tests, V3.x
  `ArchivalEngine` precursor tests) from `shekyl-economics`
  constant changes.
- **`Mock*` types implement the trait *contract*, not just the
  syntactic surface (Round 4b — Item 3).** Each `Mock*` honors
  the semantic guarantees the trait promises: `MockLedger::apply_scan_result`
  produces the conditional idempotency per §4 (same `ScanResult`
  against same starting `synced_height` → same outcome; advanced
  height → `RefreshError::ConcurrentMutation`); `MockDaemon::submit_transaction`
  produces the daemon's tx-hash dedup behavior so retry-safety
  semantics match production; `MockKey::sign_transaction` consumes
  RNG bytes from its seeded `ChaCha20Rng` so signature shapes are
  deterministic given the same inputs but distinct across calls.
  (Post-M3 + Post-PR-4 note: PR 3 shipped without a
  `MockKey` type per
  [`STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
  §6.4's no-Mock substrate; PR 4 additionally retired
  `MockLedger` (C6β = `e94526dec`; replaced by
  `FaultInjecting<L: LedgerEngine>` composed against
  `LocalLedger::from_test_blocks`) and `MockRefresh`
  (C6α = `e9310542a`; replaced by `FaultInjecting<R:
  RefreshEngine>` composed against `LocalRefresh` via the
  `Engine::replace_refresh` test-only setter); the
  contract-fidelity discipline applies to the surviving
  Mock-X types for traits where the Mock-X pattern persists
  at V3.0 baseline (`MockDaemon`, `MockEconomics`,
  `MockPersistence`, `MockPendingTx`) AND to
  `FaultInjecting<...>` wrappers, which honor the trait
  contract by delegating to the wrapped real production
  implementor's behavior — the wrapper-injected failures
  fire BEFORE or AFTER delegation per the wrapper's
  documented semantics, not by substituting alternative
  return values that contradict the trait contract.)
  Tests that assume a `Mock*` returns arbitrary plausible values
  fail to test the production code's behavior — they test the
  test harness's behavior. The contract-fidelity discipline
  applies to error variants, idempotency conditions,
  cancellation classes, and any state observable through the
  trait surface; it does not apply to performance characteristics
  (mocks are intentionally faster than production
  implementations) or to internal state representations
  (mocks may hold simpler internal data than production types).

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

**Master-seed-derivation contract for hybrid composition (Round 5
— Item 5).** When a single test composes multiple `Mock*`
instances — and especially when §6.3's hybrid construction puts
real engines and mock engines into the same test — independent
seeds per component create a reproducibility hazard: the test's
behavior depends on the *combination* of seeds, but only the
seeds passed to mocks are surface-visible (real engines'
internal randomness sources are not test-controlled in the same
way). A test that asserts on aggregate behavior across several
mocked components becomes hard to reproduce because the failure
hinges on a seed combination, not a single seed.

The discipline is therefore: **a single master seed per test
case, deterministically derived into per-component seeds.** The
test harness owns the master seed (a literal in the test
function, recorded in CI logs); per-component seeds are derived
from the master via a documented derivation function — typically
a domain-separated HKDF or BLAKE2b expansion keyed by the
component's role:

```rust
let master_seed: [u8; 32] = [0xde, 0xad, 0xbe, 0xef, /* … */];
let key_seed     = derive_seed(&master_seed, b"role/key");
let ledger_seed  = derive_seed(&master_seed, b"role/ledger");
let daemon_seed  = derive_seed(&master_seed, b"role/daemon");
let key    = MockKey::with_seed(key_seed);
let ledger = MockLedger::with_seed(ledger_seed);
let daemon = MockDaemon::with_seed(daemon_seed);
```

The role tag is a stable byte string per component slot; the
derivation function lives in `engine::test_support` so all
hybrid tests use the same construction. Reproducibility then
depends on the master seed alone — recording the master seed in
test names or CI logs (per the §6.2 single-mock rule) is
sufficient to reproduce hybrid behavior. Cross-component seed
exchange is unnecessary because the derivation pins the
relationship; per-component seed editing is unnecessary because
changing the master seed re-derives all components consistently.

This rule does *not* require per-test bespoke derivation
plumbing — the helper lives once in `test_support`; tests call
it with their literal master seed and the published role tags.
Reviewers checking new hybrid tests confirm the derivation
helper is used (rather than independent literal seeds per
mock), and confirm that role tags are not re-bound to different
component slots across tests.

### 6.3 Hybrid construction across stage migrations (Round 4b — Item 12)

The seven traits admit *hybrid* test compositions: real
implementing types for some traits, `Mock*` types for others.
The clearest motivating case is integration-flavored tests that
exercise the real `KeyEngine` (because the real key arithmetic
is what's being tested) against a `MockLedger` and `MockDaemon`
(because the test is not exercising chain state or RPC). The
hybrid is valuable: it tests a production code path with
production crypto without standing up the full chain-and-network
infrastructure.

The hybrid is also where the §6.1 mock-vs-contract discipline
compounds. When all engines are real, the trait surface's
contract is what the production implementations satisfy. When
all engines are mocked, the trait surface's contract is what the
test scaffolding declares. **In a hybrid, the real engines
interact with mock engines through the trait surface, and they
do so under the assumption that the mocks satisfy the contract
the real engines would have offered to their real counterparts.**
Mock engines that satisfy syntactic surface but not semantic
contract produce hybrids that compile but fail to test the real
engine's behavior — the real engine's retry logic, error
handling, or idempotency assumptions silently break against a
mock that doesn't honor the contract.

The discipline is therefore: **`Mock*` types in any hybrid
composition must satisfy the full §6.1 contract.** Specifically:

- Idempotency conditions documented in §4 hold for the `Mock*`
  implementor: `MockDaemon::submit_transaction` dedupes by tx
  hash exactly as the real daemon does, because that is the
  documented condition `PendingTxEngine::submit` (real or mock)
  derives its retry safety from per §5.2.
- `RuntimeFailure` semantics per §5.1 hold: a `Mock*` that
  produces `RuntimeFailure` (deliberately, in a failure-injection
  test) preserves the `ActorCrashReason` distinctions
  (`PanickedDuringHandler` vs `DrainedDuringSupervisorCascade`
  vs `Permanent`), so the hybrid exercises real-engine retry
  paths against realistic failure modes.
- Cancellation contracts per §3.4.3/§3.4.4 hold: `Mock*`
  implementors of class-c methods honor the `cancel` parameter
  semantics; `Mock*` implementors of class-b methods do not
  silently cancel on drop in violation of the documented
  drop-observation-only contract.

Authors of hybrid tests document which engines are real vs mock
in the test's setup, and reviewers confirm the contract
discipline holds for the mocked engines. Hybrid tests are not a
shortcut around the contract; they are a focused application of
it that depends on the contract being honored at every mock
seam. Determinism in hybrid composition is governed by §6.2's
master-seed-derivation contract: real engines whose internal
randomness sources accept seeds (e.g., a real
`KeyEngine::with_seed` constructor in test mode) draw their seed
from the same master seed via the published role-tag derivation,
keeping reproducibility a function of the master seed alone
across the real/mock boundary.

**Cross-stage applicability.** The discipline holds across
Stage 1 → Stage 4: at Stage 1 the `Mock*` types substitute for
concrete in-process implementations; at Stage 4 the same
`Mock*` types substitute for actor-backed implementations. The
trait surface is preserved across the cutover (per §7), and the
contract the `Mock*` types satisfy is the same contract in both
stages. Hybrid tests written against Stage 1's traits continue
to compile and pass at Stage 4 without modification, because
the contract — not the implementation — is what the test
exercises.

This is the operational reason §6.1's mock-vs-contract bullet
exists: hybrids are where contract violations cease to be
hypothetical. A `Mock*` that drifts from the contract works in
all-mock tests (because nothing real depends on the contract)
and breaks in hybrid tests (where a real engine depends on the
mock honoring the contract). Pinning the discipline at §6.1 and
operationalizing it at §6.3 is the trait-spec-side prevention
of this drift.

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
   2 refinement; checkpoint 5 added per PR 4 Round 4 F2). The
   five checkpoints are:

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
   3. **Mid-scan, between blocks** — owned by
      `RefreshEngine::produce_scan_result`. Covers cancels
      between blocks during the long scan phase, where the bulk
      of elapsed time lives.
   4. **Pre-merge** — owned by the orchestrator. Covers the
      post-scan window where a valid `ScanResult` has been
      returned but the write borrow for `apply_scan_result` has
      not yet been acquired.
   5. **Per-transaction, inside the per-block scan loop** —
      owned by `RefreshEngine::produce_scan_result`. Added per
      [`STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
      §5.4.9 F2 to bound wallet-lock latency under adversarial
      daemon block-crafting to per-transaction scan time
      rather than per-block scan time. **Safe-point pin
      (F11 + F11-S, binding):** fires at the top of the
      per-transaction iteration, **after** the prior iteration's
      `Zeroizing<…>`-wrapped per-output materials have dropped
      at scope exit, **before** the next transaction's
      view-tag / hybrid-decap / key-image derivation begins.
      Mid-derivation firing is **forbidden** — the cancellation
      must not interleave with a partially-derived per-output
      secret whose `Drop` chain has not yet completed.
      Implementors **measure** `recover_outputs_in_tx`'s
      per-output marginal cost on reference hardware and
      escalate the safe-point granularity to per-output
      (between consecutive per-output decap iterations within
      the per-tx loop, with the same safe-point semantics)
      when worst-case per-tx scan time under maximum-output
      hostile transactions exceeds the §3.1 sub-block
      lock-latency target.

   No post-merge checkpoint by design. Once `apply_scan_result`
   commits, the merge is authoritative and a cancel observed
   afterward cannot un-mutate the wallet.

   The Stage 4 actor for `RefreshEngine` and the Stage 4
   orchestration on `Engine` observe the same checkpoints in the
   same order with the same ownership split between trait
   (checkpoints 2, 3, 5) and orchestrator (checkpoints 1, 4).

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
| `LedgerEngine` | (none) | Second. Required by `RefreshEngine` (snapshot/merge) and `PendingTxEngine` (which depends on `LedgerEngine`'s ownership of the underlying `LedgerBlock` state used for output selection — the prerequisite is structural state-ownership, not trait-method consumption from the build path; see §2.2 for the access-path framing and §2.2's 2026-05-03 transfer-clone discipline amendment for why no trait-level transfer-enumeration method exists). |
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

### 8.2 Stage-1-amendment co-landing rule (Round 4b — Item 2)

If a Stage 1 implementation surfaces the need for a trait-method
addition that wasn't pinned in this spec — e.g., during the
`DaemonEngine` PR's implementation, the author discovers that
`Rpc::get_block_header` lacks an overload that the
`RefreshEngine` consumer needs — the addition follows a
**two-commit form** within the same PR:

1. **Trait amendment commit.** Adds the new trait method to
   §2's surface, updates relevant rustdoc, updates the §4
   async-story table with a row for the new method (including
   cancel class and idempotency per §1.6 documentation
   discipline), updates the `Mock*` implementor with a default
   that satisfies the trait contract per §6.1, and adds a
   "Round N amendment" sub-bullet to the relevant §2.X section
   explaining why the addition was needed.
2. **Consumer commit.** Implements the consumer code that uses
   the new trait method.
3. **PR description names the amendment explicitly.** The PR
   description identifies the trait amendment by method name
   and motivation ("This PR adds
   `Rpc::get_block_header_at_hash` to satisfy `RefreshEngine`'s
   reorg-detection path"), so reviewers can scope their
   attention to the spec impact and confirm §7's invariants
   hold (amendments are additive only; they must not change
   existing method signatures, async-ness, error type, or
   ownership semantics). Amendments that violate §7 are not
   amendments — they re-open this spec for a new round, and
   the PR description must surface that explicitly rather than
   buried in commit-message bodies.

Why these three are structurally separate (Round 5 — Item 6).
The two-commit form is a **bisection discipline**: trait
additions affect every implementor (Stage 1 default impl, every
`Mock*`, future Stage 4 actor) by virtue of the `T: KeyEngine`
bound now requiring the new method, so trait amendments must be
revertible independently of consumer changes for bisection to
land at the right granularity if a regression surfaces later.
The PR-description bullet is a **review-scope discipline**: it
tells human reviewers where the spec impact lives so they can
confirm §7's invariants hold without reading the entire diff.
Together the three bullets cover three audiences operating at
three granularities — bisecting tools at commit granularity, PR
reviewers at PR granularity, and future readers at spec-amendment
granularity via the §2.X "Round N amendment" sub-bullet. Each
bullet serves an audience the others cannot: bundling commits
would conflate the bisection discipline; omitting the
PR-description bullet would conflate the review-scope discipline;
omitting the §2.X amendment sub-bullet would conflate the
spec-archaeology discipline (future readers asking "when was
this method added and why?" would have to grep commit history
rather than reading the spec). Reviewers applying §8.2
mechanically check all three bullets; missing any one weakens
the discipline's enforcement against the corresponding audience.

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

**Round 4a closure (this round).** Twenty design-closure items
landed across Phases 1, 2a, 2c, and 2b/3. The §10 deferred
subsection (Item 8) is the final substantial Round 4a
deliverable; with it landed, the spec's forward-work map is
authoritative and Round 4b's mechanical fill-in proceeds against
a stable framework.

**Round 4b dispositions (18 items across two phases — all
landed).**

*Phase 1 — carry-forwards (11 items, committed at `143b965bc`):*

- Per-method drop-cancellation classification → §4 cancel-class column (Item 1).
- Stage-1-amendment co-landing rule → new §8.2 (Item 2; Phase 2 polish: PR-description third bullet).
- Mocks-vs-contract pin → §6.1 bullet (Item 3).
- Seven-traits-Stage-1-only / Phase-2b-additive pin → §1.2 preamble (Item 4).
- `#[tokio::test]` rustdoc clarification → §4.2 (Item 5).
- Panic-rustdoc requirement → new §1.6 documentation discipline (Item 6).
- §1.5 `StakeEngine` positive example → §1.5 hypothetical-evaluation block (Item 7).
- §3.5 long-running-operation paragraph → §3.5 (Item 8).
- `docs/PERFORMANCE_BASELINE.md` template stub → new file (Item 9).
- `docs/FOLLOWUPS.md` V3.0 baseline entry → FOLLOWUPS V3.0 (Item 9).
- `docs/FOLLOWUPS.md` V3.x cutover-CHANGELOG entry → FOLLOWUPS V3.x (Item 10).
- §10.0 separator visual-weight strengthening → §10.0 (Item 11).

*Phase 2 — gap-check additions (7 items, this commit):*

- §1.4 `Send`-on-parameters discipline → §1.4 paragraph addition (Item 18).
- §3.3.1 baseline definition → §3.3.1 in-place tightening (Item 14).
- §3.4.4 long-running cancellation pattern → new §3.4.4 (renumbers existing dispositions to §3.4.5; Item 16).
- §5.1 supervisor restart-budget acknowledgement → §5.1 paragraph addition (Item 17).
- §5.2 caller retry contract → new §5.2 (with PendingTx/Daemon layered-call pinning; Item 13).
- §6.3 hybrid construction discipline → new §6.3 (Item 12).
- §10.1.3 verification gates + orthogonal-properties exclusion → §10.1.3 in-place extension (Item 15).

*Phase 1 cross-reference closures landed in Phase 2:*

- §1.6 idempotency bullet → §5.2 cross-reference (closes the Phase 1 forward-reference once §5.2 lands).
- §3.5 long-running paragraph → §3.4.4 reference cleanup (drops the "forthcoming in Round 4b Phase 2" parenthetical now that §3.4.4 lands).

**Round 5 dispositions (9 items + panic-strategy enumeration
extension — all landed in this commit).**

*Pre-drafting gap-check.* Three framings applied: ("implicit but
discoverable late" in unaddressed domains), ("what would Stage
2's first PR reviewer ask?"), ("what would Phase 2b's
`StakeEngine` spec author cite?"). All three produced zero
structural items, confirming the spec's structural decisions
remained settled across multiple lenses. One strong operational
candidate — **panic strategy** (`panic=abort` vs `panic=unwind`)
— surfaced from the first framing as a deployment-context
property the spec implicitly depends on (§5.1's supervisor
design assumes `panic=unwind`); absorbed via enumeration
extensions in §10.1.3 and §10.6.4 rather than added as a tenth
agenda item. One weak candidate (TLS in trait implementations)
deferred — §1.4's actor-shape discipline already prevents it
implicitly. **Case A confirmed**: spec is structurally complete;
Round 6 is unnecessary; Round 5 is the acceptance round.

*Items 1–9 (this commit):*

- Status block SHA update for Round 4b Phase 2 record →
  `0d8ff9ef0` (Item 1).
- §3.3.1 re-baseline policy → §3.3.1 in-place extension
  (frozen-numbers-at-first-Stage-1-PR; per-PR-deltas; Stage-1-close
  framing; Item 2).
- §3.4.4 progress-channel backpressure with §10.4.3 consistency →
  §3.4.4 paragraph addition (unbounded-by-default at V3.0;
  V3.x-deferred with the same trigger conditions as §10.4.3;
  Item 3).
- §5.2 layered-call error preservation (verbatim-not-wrapping) +
  three-case walk table-form polish → §5.2 in-place extension
  (table summary precedes prose; verbatim preservation rule
  elevates `EngineError` aggregate as the natural carrier;
  Item 4).
- §6.2 master-seed-derivation contract for hybrid composition +
  §6.3 cross-reference → §6.2 paragraph addition + §6.3 closing
  paragraph (master seed in `engine::test_support`; per-component
  seeds derived via stable role tags; Item 5).
- §8.2 two "Why" paragraphs consolidated into single
  "Why these three are structurally separate" framing → §8.2
  in-place rewrite (three audiences × three granularities;
  bisecting tools / PR reviewers / spec archaeology; Item 6).
- §10.1.3 fifth bullet for deployment-context properties (incl.
  panic strategy with spec-dependent honesty pin) +
  resource-consumption cross-reference to §10.2.2 → §10.1.3
  in-place extension (Item 7).
- New §10.6.4 deployment-configuration pinning re-litigation
  entry (4 enumeration items: allocator, TLS, tokio runtime
  config, panic strategy; spec-indifferent vs spec-dependent
  distinction; Item 8).
- §1.5 sixth scope guard
  (deployment-configuration-as-binary-concern), back-filled from
  §10.6.4 final framing → §1.5 enumeration addition (Item 9).

*Round-count.* Five rounds (1, 2, 3, 4a, 4b, 5) at the upper
bound of the 4–6 review-rounds rule. The structural depth (seven
traits × Stage 1/2/4 surfaces × V3.0/V3.1/V3.2/V3.x/Phase 2b
lifecycle horizons) earned the thorough pressure-testing across
nine "what are we missing" cycles; yield trended structural →
design-closure → operational-refinement, with the late-round
yield staying low in count and impact (the diminishing-returns
signal the round count was designed to surface).

---

## 10. Out of scope / Deferred (Round 4a — Item 8)

This section is the spec's authoritative forward-work map. Each
entry pins (a) what is deferred, (b) the trigger that closes
the entry, (c) the structural decision in this spec that
governs the deferred work, and (d) the dependencies that gate
it. Entries grouped by axis; intra-group ordering reflects
dependency flow.

### 10.0 Dependency overview

The dependency graph below shows how the 16 deferred entries
chain. Each axis names the Round 4a section(s) governing it;
each entry within an axis has dependencies on prior entries
(intra-group) or on other axes (inter-group). The graph is
rendered as ASCII art optimized for GitHub markdown, which is
this spec's primary review surface (PR #20). Non-GitHub
viewers may strip whitespace; the source markdown carries the
graph faithfully.

```
Round 4a closure (the ground truth)
    │
    ├──► §10.1 Stage transitions axis  (governed by §1.4, §2.8, §3.3, §3.4, §5.1)
    │      §10.1.1 Stage 1 → 2 transition mechanics
    │         └──► §10.1.2 Stage 4 per-actor mailbox cutover (Path B)
    │                 ├──► §10.1.3 Stage 4 behavioral-equivalence verification
    │                 ├──► §10.2.2 Stage 4 cost characterization
    │                 ├──► §10.4.1-design Adaptive-burn observation design hook
    │                 └──► §10.4.3 Bounded-mailbox triggers
    │
    ├──► §10.2 Performance characterization axis  (governed by §3.3 measurement gate)
    │      §10.2.1 Stage 1 baseline (V3.0; gates Stage 1 PR review)
    │      §10.2.2 Stage 4 cost characterization (depends on §10.1.2)
    │
    ├──► §10.3 V3.1 / V3.2 expansion axis  (governed by §2 trait surfaces, §2 preamble visibility)
    │      §10.3.1 Multisig support (V3.1)
    │         └──► §10.3.2 Multi-engine server (V3.1+)
    │                 └──► §10.3.3 JSON-RPC server cutover (V3.2; promotes pub(crate)→pub)
    │
    ├──► §10.4 V3.x enhancement axis  (governed by §2.7, §2.8, §3.4, §7)
    │      §10.4.1 Adaptive-burn observation feeding (design hook on §10.1.2)
    │      §10.4.2 FCMP++ progress trigger (evidence-gated)
    │      §10.4.3 Bounded-mailbox triggers (depends on §10.1.2)
    │      §10.4.4 Anonymity-network coordination
    │
    └──► §10.5 Phase 2b trait expansion axis  (governed by §1.5 criteria)
           §10.5.1 StakeEngine design (validates §1.5 against an additive trait)

═══════════════════════════════════════════════════════════════════════════
                  SCOPE-GUARD REVISIT-TRIGGER ENTRIES
              (target: REMAIN REJECTED unless threshold met;
                   closure is NOT the success state)
═══════════════════════════════════════════════════════════════════════════

§10.6 Scope-guard revisit-trigger entries
    §10.6.1 8th-trait proposals beyond Phase 2b (governed by §1.5 + scope-guard meta-pattern)
    §10.6.2 Trait-level observability re-litigation (revisits §3.5)
    §10.6.3 Consensus-rule enforcement re-litigation (revisits §2.7 scope guard)
    §10.6.4 Deployment-configuration pinning re-litigation (revisits §10.1.3 fifth bullet)
```

The visual separator below §10.5 is load-bearing: §10.6's
entries follow a fundamentally different format and represent
a different category of deferred work. The five version-gated
axes (§10.1–§10.5) target *closure* — every entry is intended
to complete and be removed from §10 when it ships. §10.6's
three entries target *remaining rejected* — every entry's
success state is "the rejection still holds; revisit not
warranted." Conflating these two categories visually invites
reviewers to read §10.6 as "things that will eventually
happen, just at unknown times," which is the wrong reading.

**Entry lifecycle.** Trigger-firing schedules the work for the
appropriate stage; trigger-firing is *not* the same as
work-completion. Each entry remains in §10 until the work
ships, at which point it moves to `CHANGELOG.md` and is
removed from §10. §10.6 entries do not have a ship event in
the same sense; they remain in §10 as long as the rejection
holds, and would only be removed if the revisit threshold is
met and the rejected proposal is adopted.

**Trigger discipline (external vs internal).** Each entry's
trigger is annotated as either *external* (owned by a document
or phase outside this spec — e.g., "Phase 2b design phase
begins" is external) or *internal* (produced by this spec's
own machinery — e.g., "§3.3 measurement gate produces
out-of-threshold result" is internal). External triggers
require periodic checking against the named owner's status;
internal triggers fire when the spec's own work reaches the
named milestone. The annotation makes the tracking story
visible.

**Format note.** Entries in §10.1–§10.5 use a **closure-targeted
format**: Description / Trigger / Structural cross-reference /
Dependencies, with an optional fifth *Design start vs ship
distinction* block on entries where the design happens before
the ship. Entries in §10.6 use a **revisit-threshold format**:
Description / Original rejection / Revisit threshold (three
named requirements). The format split is structural — different
question, different answer shape — not stylistic. §10.6's
sub-subsection introduction repeats this distinction inline so
readers reaching §10.6 directly do not miss it.

### 10.1 Stage transitions

Three entries on the path from Stage 1's `Arc<RwLock<Engine>>`
to Stage 4's per-actor mailbox cutover (Path B). Sequential
dependencies: each entry depends on the prior.

#### 10.1.1 Stage 1 → 2 transition mechanics (target: Stage 2)

*Description.* The gradual move from outer-`RwLock` (Stage 1)
to per-trait inner locking that prepares the surface for
mailbox cutover (Stage 2). Stage 2 is an intermediate state
where each implementing type owns its own internal locks at
operational granularity — what the §2 sweep already pinned at
the trait surface — but the outer `Arc<RwLock<Engine>>` is
still in place. This intermediate state lets the migration to
Stage 4 happen incrementally rather than as a flag-day cutover.

*Trigger.* "Stage 1 ships and the §3.3 measurement gate's
results are documented in `docs/PERFORMANCE_BASELINE.md`."
(Internal — produced by §3.3 measurement gate completion.)

*Structural cross-reference.* §3.3.1 Stage 1 outer-lock
sequential consistency; §3.3.2 Stage 4 per-actor mailbox FIFO;
the `RefreshHandle ships transitional Arc-RwLock-Engine under
Path B` decision-log entry (2026-04-27).

*Dependencies.* Stage 1 implementation lands and §10.2.1
performance baseline measurements are documented (the
measurement gate's results inform whether Stage 2 needs to
defer specific lock reductions or can proceed broadly).

#### 10.1.2 Stage 4 per-actor mailbox cutover (Path B) (target: Stage 4)

*Description.* The cutover from outer-`RwLock` to per-actor
`kameo` mailboxes with supervisor strategies. Stage 4
activates the spawn graph (§2.8.3), the supervisor model
(§5.1), the cancellation discipline at actor boundaries (§3.4),
the lifecycle async-public surface (§2.8.3), and the
per-method drop-cancellation classifications (§3.4.3, with
Round 4b's per-method table). The trait surfaces are
preserved verbatim per §7's invariants; the implementing
types swap from `Local*` (interior-mutability over owned
state) to `*Actor` (per-actor mailbox) at this boundary.

*Trigger.* "Stage 1 → 2 transition mechanics complete and
Stage 4 design document settles." (Internal — produced by
§10.1.1 completion plus the explicit design-document
settlement.)

*Structural cross-reference.* §1.4 actor-shape discipline
(the constraint that survives the cutover); §2.8 lifecycle
(the spawn / landing / teardown graphs that activate);
§3.3.2 Stage 4 mailbox semantics; §3.4 cancellation
discipline; §5.1 supervisor strategy and `RuntimeFailure`;
§7 trait surface stability invariants.

*Dependencies.* §10.1.1 (Stage 2 prepares the per-trait
locking surface that Stage 4 then swaps to mailboxes); the
`shekyl-engine-core` codebase having a `kameo` integration
that doesn't currently exist (separate implementation work).

#### 10.1.3 Stage 4 behavioral-equivalence verification (target: Stage 4 cutover-time)

*Description.* The Stage 4 cutover changes the
implementation surface (mailboxes vs locks) but is constrained
by §7 to preserve the trait surface verbatim. Verification
that the cutover actually preserves observed behavior across
§7's checkpoints (post-tip-fetch ownership, five-checkpoint
cancellation discipline, idempotency conditions per §4) is
not automatic — the implementations are different, and
"identical behavior" must be demonstrated, not assumed.

The verification methodology is open at Round 4a: candidate
approaches include property-based testing with shared
`Mock*` implementors driving both Stage 1 and Stage 4
implementations through identical scenarios; differential
testing where Stage 1 traces and Stage 4 traces are diffed
under deterministic seeds; manual code-review
correspondence per §3.2's call-site disposition table. The
chosen methodology is part of the Stage 4 cutover PR's
review discipline, not part of this spec.

**Gates (Round 4b — Item 15).** Verification is *binding*
before Stage 4 cutover merges to `dev`. The cutover PR
(§10.1.2) cannot land until the chosen methodology has
produced evidence that the gated properties hold:

- §7 invariants 1–4 are demonstrated against the cutover
  implementation under the methodology's test scenarios
  (trait surface stability, post-tip-fetch checkpoint
  ownership, five-checkpoint cancellation discipline,
  checkpoint ownership split).
- Per-method idempotency conditions per §4 are verified —
  methods marked "yes" produce identical observable outcomes
  on repeat invocation against the actor-backed
  implementation; methods marked "conditionally" honor the
  documented condition; methods marked "no" are exercised
  with single invocation only.
- §5.1's `RuntimeFailure` semantics — `PanickedDuringHandler`
  vs `DrainedDuringSupervisorCascade` vs `Permanent`; the
  mailbox-FIFO draining ordering — are exercised through
  deliberate panic injection in the test methodology.

The verification evidence (test logs, property-based
assertions, differential traces, methodology-specific
artifacts) lands in the Stage 4 cutover PR's review surface
so reviewers confirm the gate's discharge before approving
merge.

**Orthogonal properties explicitly excluded from §10.1.3
(Round 4b — Item 15).** Verification gates the properties §7
makes invariant — *behavioral equivalence on the trait
surface*. The following are *not* part of behavioral
equivalence and are gated separately:

- *Performance characterization.* Stage 4 latency and
  throughput are gated by §10.2.2; performance regression
  detection has its own evidence-and-disposition mechanism.
- *Observability output.* Tracing emissions per §3.5 may
  legitimately differ between Stage 1 (synchronous spans)
  and Stage 4 (actor-handler spans). Observability shape is
  call-site-driven (per §3.5's rejection of trait-level
  observability hooks); it is not part of the trait surface.
- *Operational characteristics.* Restart-budget values per
  §5.1, mailbox-bounding triggers per §10.4.3,
  supervision-strategy choices per §5.1 — these are
  deployment parameters and operator-tuned settings, not
  trait-surface properties.
- *Resource consumption.* Memory footprint, file-descriptor
  count, thread/task count differ between stages by
  construction (Stage 1 has no actor tasks; Stage 4 has one
  task per actor). These are implementation-orthogonal to
  behavioral equivalence; resource-consumption deltas
  attributable to Stage 4's actor model (per-actor task
  overhead, mailbox memory, additional FD usage from
  supervision plumbing) are gated by §10.2.2 alongside
  performance characterization, not by §10.1.3.
- *Deployment-context properties (Round 5 — Item 7).*
  Allocator behavior (system, jemalloc, mimalloc), TLS
  implementation choice (rustls vs native-tls), tokio
  runtime configuration (worker thread count, blocking pool
  size), and panic strategy (`panic=abort` vs `panic=unwind`)
  are properties of the deployment context outside the
  wallet engine's trait surface. Three of these (allocator,
  TLS, tokio runtime config) are spec-indifferent; the
  fourth (panic strategy) is spec-dependent — §5.1's
  supervisor design assumes `panic=unwind` so that
  `PanickedDuringHandler` semantics are observable, but the
  spec does not enforce the binary build configuration that
  satisfies the assumption. §10.6.4 names the assumption
  explicitly so binaries built with `panic=abort` are known
  to be out of contract for the supervisor mechanism. All
  four are governed by binary-level build configuration and
  operator-tuned settings, not by trait-level invariants;
  effects on performance or observability are gated by
  §10.2.2 (performance) or §3.5 (observability), not by
  §10.1.3.

Each excluded property has its own verification path —
separate gate, separate documentation, separate review
discipline. The exclusion is structural, not dismissive:
folding these into §10.1.3 would conflate "the trait surface
preserves behavior" with "the implementation has acceptable
operational characteristics" — two distinct properties with
two distinct verification mechanisms. §10.1.3 governs the
former; the named cross-references govern the latter.

*Trigger.* "Stage 4 per-actor mailbox cutover begins." (Internal
— produced by §10.1.2 starting; verification runs
concurrently with cutover work.)

*Structural cross-reference.* §7 invariants 1–4
(trait-surface stability, post-tip-fetch checkpoint
ownership, five-checkpoint cancellation discipline,
checkpoint ownership split); §6 test boundary (the mock
infrastructure that makes shared-driver testing possible);
§3.2 call-site disposition table.

*Dependencies.* §10.1.2 (the cutover whose behavior is being
verified) plus a methodology choice (currently open; resolution
required at Stage 4 design phase).

### 10.2 Performance characterization

Two entries split by stage. Stage 1's gate is V3.0 (binding
before Stage 1 PRs land per §3.3); Stage 4's characterization
is cutover-time and structurally distinct.

#### 10.2.1 Stage 1 baseline measurement (target: V3.0 — gates Stage 1 PR review)

*Description.* The §3.3 measurement gate operationalized:
`criterion`-driven benchmarks of read-path overhead for the
hot paths enumerated in §3.3 (`KeyEngine::account_public_address`,
`LedgerEngine::balance`, `LedgerEngine::synced_height`,
`EconomicsEngine::current_emission`,
`EconomicsEngine::parameters_snapshot`), plus any additional
hot paths reviewer judgment identifies during PR review.
Results land in `docs/PERFORMANCE_BASELINE.md` (template
stub from Round 4b) with methodology, baseline numbers,
post-interior-lock numbers, and percentage delta per path.
Reviewers cite the document during Stage 1 PR review;
§3.3's threshold-of-concern (>10% requires PR-description
justification; >25% requires optimization before merge)
governs disposition.

*Trigger.* "First Stage 1 implementation PR opens." (Internal
— produced by Stage 1 implementation work beginning.)

*Structural cross-reference.* §3.3 interior-mutability
measurement gate (the three pinned components: measurement,
documentation, threshold); §2 sweep (the interior-mutability
choices being measured).

*Dependencies.* `docs/PERFORMANCE_BASELINE.md` template stub
(Round 4b); a `criterion` benchmark harness in the
`shekyl-engine-core` test directory (separate
implementation work).

#### 10.2.2 Stage 4 cost characterization (target: Stage 4 cutover-time)

*Description.* The Stage 4 cutover introduces costs
the §3.3 Stage 1 gate does not measure: per-actor mailbox
message-passing overhead, supervisor restart cost on
`RuntimeFailure`, mailbox depth under burst load, and the
Path B cost-savings (the redundant interior locks of §3.3
disappear). Characterization at cutover lets the release
decision weigh "did we save what we expected; did we
introduce costs we didn't expect." Comparison baseline is
Stage 1's `PERFORMANCE_BASELINE.md` numbers.

*Trigger.* "Stage 4 per-actor mailbox cutover reaches
implementation-stable state." (Internal — produced by
§10.1.2 reaching review-ready state.)

*Structural cross-reference.* §3.3 (the Stage 1 baseline this
characterization compares against); §3.3.2 Stage 4 mailbox
semantics (the costs being characterized); §5.1 supervisor
strategy (restart costs).

*Dependencies.* §10.1.2 implementation reaching stable state;
§10.2.1 baseline numbers in hand for comparison.

### 10.3 V3.1 / V3.2 expansion

Three entries in version-sequential order. V3.1's multisig
adds structural complexity to two traits; V3.1+ multi-engine
server changes the assumed engine-per-process model; V3.2's
JSON-RPC cutover promotes the trait visibility per §2
preamble. Sequential dependencies: each entry depends on the
prior settling.

#### 10.3.1 Multisig support (target: V3.1)

*Description.* Stage 1's surface assumes single-signer flows.
Multisig adds round-trip signature aggregation, partial-sign
protocols, and threshold-handshake state that materially
extends `KeyEngine` (multi-party signing primitives) and
`PendingTxEngine` (partial-signature collection, multi-round
build phases). The multisig design phase produces a separate
design document; the trait surface implications land here as
additive methods that respect §2.7's consumer-driven
justification rule and the §1.5 trait-identity criteria
(specifically: multisig may justify a `MultisigEngine` as
the 8th trait if it clears §1.5; or it may live as method
extensions on `KeyEngine` and `PendingTxEngine` if it
doesn't).

*Trigger.* "V3.1 multisig design phase begins." (External —
owned by V3.1 release planning; tracked against project plan.)

*Structural cross-reference.* §2.1 `KeyEngine`; §2.6
`PendingTxEngine`; §1.5 trait-identity criteria (for
evaluating whether multisig is its own trait); §2.7's
consumer-driven justification rule (for any new methods).

*Dependencies.* V3.0 ship (Stage 1 lifecycle firm); V3.1
multisig economic / consensus design (separate document; not
in this spec).

#### 10.3.2 Multi-engine server (target: V3.1+)

*Description.* `Engine<S>` currently assumes one wallet per
engine instance (one process embeds one engine; one engine
serves one wallet). Server use cases (custodial wallets,
multi-tenant hosted wallets) want N engines per process. The
question whether N engines share actors (e.g., one
`DaemonActor` serving all engines' RPC needs) or each engine
is fully isolated is open; the choice affects supervisor
strategy at Stage 4 (per-engine vs shared-actor failure
domains) and the §5.1 `RuntimeFailure` enumeration's `actor`
field (which actor failed: engine A's, engine B's, or the
shared one?).

*Trigger.* "V3.1+ multi-engine-server design phase begins."
(External — owned by V3.1+ release planning; depends on
multisig settling first because multi-engine adds isolation
concerns on top of the multisig surface.)

*Structural cross-reference.* §3 composition (`Engine<S>`'s
type-parameter ordering and Stage 4 transition); §2.8
lifecycle (the spawn graph activates per-engine or
per-shared-actor); §5.1 supervisor strategy (the failure
isolation question).

*Dependencies.* §10.3.1 multisig (the multi-engine isolation
concerns are materially affected by whether each engine has
multisig state); V3.0 ship.

#### 10.3.3 JSON-RPC server cutover (target: V3.2)

*Description.* The `wallet_rpc_server` Rust migration per
`docs/FOLLOWUPS.md` V3.2 target. At cutover, the seven
traits promote from `pub(crate)` (per §2 preamble Item 13)
to `pub`; the trait surface becomes part of the public API.
Promotion is additive and does not require trait-surface
changes — only visibility relaxation — but it changes the
test-boundary discipline (per §6, integration tests against
`Mock*` implementors no longer need to live in-crate).

*Trigger.* "V3.2 `wallet_rpc_server` Rust migration phase
begins." (External — owned by V3.2 release planning per
`docs/FOLLOWUPS.md`.)

*Structural cross-reference.* §2 preamble visibility pin
(Round 4a Item 13); §6 test boundary; `docs/FOLLOWUPS.md`
V3.2 entry.

*Dependencies.* §10.3.1 multisig and §10.3.2 multi-engine
server (both feed into the public API surface); V3.0 ship.

### 10.4 V3.x enhancements

Four entries that ship at V3.x but vary in design-start
timing. Entries with Stage 4 design hooks carry the optional
fifth block (*Design start vs ship distinction*).

#### 10.4.1 Adaptive-burn observation feeding (target: V3.x; design hook: Stage 4)

*Description.* Component 3's adaptive burn requires
`EconomicsEngine` to observe network activity (transaction
throughput, fee distribution, congestion metrics). The
"who feeds the observation" question — `LedgerActor`
publishing block-event subscriptions that the
`EconomicsActor` consumes; an explicit
`EconomicsEngine::observe_block(block)` method on the trait
surface; a background subscription managed by `Engine<S>`
orchestration — is open at V3.0. The `EconomicsEngine`
trait surface is preserved verbatim per §7's invariants
regardless of the resolution.

*Trigger.* "Component 3 adaptive-burn design phase begins."
(External — owned by Component 3 economic-design phase
planning.)

*Design start vs ship distinction.* The *ship* is V3.x. The
*design hook* is Stage 4 cutover: any "background
subscription from `LedgerActor` to `EconomicsActor`"
mechanic requires Stage 4's per-actor mailbox framework to
be operational, and the inter-actor message-passing surface
for that subscription is a Stage 4 design-time decision.
Deferring the design entirely to V3.x risks the Stage 4
cutover landing without the message-passing surface in
place.

*Structural cross-reference.* §2.7 `EconomicsEngine`
ownership block and adaptive-burn note; §7 trait surface
stability invariants; §1.5 consumer-driven justification rule
(applies to any new method on `EconomicsEngine`); §2.7
scope guard (consensus-as-truth: activity input is observed
from chain state, not from a wallet-side oracle);
[`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) Component 3
specification.

*Dependencies.* §10.1.2 Stage 4 per-actor mailbox cutover
(for the design hook); §2.7's consensus-as-truth pin and
`EconomicsEngine` scope guard governing the design space;
the Component 3 economic specification in
`DESIGN_CONCEPTS.md`.

#### 10.4.2 FCMP++ progress trigger (target: V3.x — evidence-gated)

*Description.* If `KeyEngine::sign_transaction`'s FCMP++
proof generation becomes user-perceptible at V3.x (current
target sub-second per single-output proof, revisable on
benchmark data), `KeyEngine` grows an in-band progress
channel per the §2.3 `RefreshEngine::produce_scan_result`
pattern (cancellation token plus progress reporter as
explicit method parameters). The progress channel preserves
the §1.4 actor-shape discipline because progress reporting
is an explicit method parameter, not an implicit
trait-surface observability hook (per §3.5's
observability-via-tracing rejection).

*Trigger.* "FCMP++ proof-time benchmark data shows
sign-time exceeds [user-perceptibility threshold]."
(Internal — produced by FCMP++ benchmark suite, which is
itself separate Round 4b / V3.x work.) The threshold is
operationally "noticeable to a UI user," typically
~200ms on interactive paths; the spec does not pin the
exact number because perception is workload-dependent.

*Structural cross-reference.* §2.1 `KeyEngine`; §2.3
`RefreshEngine::produce_scan_result` (the existing pattern
to follow); §1.4 actor-shape discipline; §3.5
observability-via-tracing rejection (the discipline that
forces in-band progress channels rather than trait-level
observability hooks).

*Dependencies.* FCMP++ proof-time benchmark suite (separate
implementation work); evidence that single-output proof
time exceeds the user-perceptibility threshold.

#### 10.4.3 Bounded-mailbox triggers (target: V3.x — evidence-gated)

*Description.* Stage 4 V3.0 ships with unbounded mailboxes
(per Round 3 disposition). Bounded mailboxes are revisited
if backpressure surfaces in production load: pathological
producer-consumer asymmetry where one trait's mailbox grows
unboundedly relative to consumption rate; OOM under burst
load attributable to mailbox backlog; message-queue stat
anomalies in observability traces. Bounded mailbox design
introduces backpressure semantics (caller blocks or fails on
full mailbox) that materially affect §3.4's cancellation
discipline and §5.1's supervisor strategy.

*Trigger.* "Production observation shows mailbox backlog
exceeds named threshold." (Internal — produced by §10.2.2
Stage 4 cost characterization or by post-Stage-4 production
operation.) The threshold is open; candidate metrics
include peak mailbox depth as fraction of available memory,
sustained mailbox depth above queue-stat anomaly thresholds,
or specific OOM events traceable to mailbox backlog.

*Structural cross-reference.* §3.3.2 Stage 4 mailbox FIFO
(the surface bounded mailboxes modify); §3.4 cancellation
discipline (bounded mailboxes change drop semantics); §5.1
supervisor strategy (bounded mailboxes change drain
semantics).

*Dependencies.* §10.1.2 Stage 4 per-actor mailbox cutover
(must ship first to produce backpressure observations);
§10.2.2 Stage 4 cost characterization (provides the
observation infrastructure that surfaces backpressure
evidence).

#### 10.4.4 Anonymity-network coordination (target: V3.x)

*Description.* Onion-routing / mixnet integration for
transaction submission and refresh queries. The integration
lives at a layer above `DaemonEngine` (a transport layer that
wraps daemon RPC calls in onion routing or mixnet
messaging), not on `EconomicsEngine`. The trait spec
assumes Stage 1's existing transport pattern (direct daemon
RPC via `DaemonClient`); V3.x design adds the
anonymity-coordination shape, potentially as an 8th trait
(`AnonymityNetworkEngine` or similar) if it clears §1.5's
trait-identity criteria, or as an interception layer
between `Engine<S>` and `DaemonEngine` if it doesn't.

*Trigger.* "V3.x archival design phase mandates
anonymization for archive queries." (External — owned by
V3.x archival design; the archival-anonymization
requirement is what brings this work into scope.)

*Design start vs ship distinction.* The *ship* is V3.x. The
*design start* is when V3.x archival design begins, which
is itself V3.x but earlier than feature-complete V3.x.
Specific timing depends on V3.x archival design phase
planning.

*Structural cross-reference.* §2.5 `DaemonEngine` (the
trait being wrapped or extended); §1.5 trait-identity
criteria (for evaluating whether `AnonymityNetworkEngine`
is its own trait); §2.7's consensus-as-truth pin (the
anonymity layer must not change consensus-derived values).

*Dependencies.* V3.x archival design (separate design
document); V3.0 ship; possibly §10.3.2 multi-engine server
(depending on whether anonymity is per-engine or
shared-transport).

### 10.5 Phase 2b trait expansion

One entry currently. Phase 2b is the structurally distinct
phase that expands the seven traits to eight (or more) via
the §1.5 criteria. Expansions in subsequent phases would land
here as additional entries.

#### 10.5.1 StakeEngine design (target: Phase 2b)

*Description.* `StakeEngine` is the canonical
candidate for Phase 2b's additive trait — it owns per-stake
records, the stake FSM state, and the principal-pool
aggregation state at Stage 4; it consumes `EconomicsEngine`
via the canonical-derivation surface (§2.7); it has explicit
cross-cutting consumers (`Engine<S>` for stake-aware
operations, future `ArchivalEngine` for sibling-actor
queries via `is_active_staker(entity_id)`, external
observers via JSON-RPC). The Phase 2b design phase produces
a separate design document; the trait surface implications
land here as the validation that §1.5's criteria correctly
predict the design's trait-existence justification.

*Trigger.* "Phase 2b design phase begins." (External — owned
by Phase 2b release planning.)

*Structural cross-reference.* §1.5 trait-identity criteria
(the framework Phase 2b validates against); §2.7
`EconomicsEngine` (the trait `StakeEngine` consumes); §2.7
scope guard (the consensus-as-truth principle constrains
`StakeEngine`'s wallet-side enforcement scope); the Phase 2b
design document (separate).

*Dependencies.* V3.0 ship; §1.5 criteria settled (Round 4a);
[`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) and
[`STAKER_REWARD_DISBURSEMENT.md`](STAKER_REWARD_DISBURSEMENT.md)
specifying the staking economics that `StakeEngine`
implements.

---

### 10.6 Scope-guard revisit-trigger entries

These three entries follow a **revisit-threshold format**
rather than the closure-targeted format used in §10.1–§10.5.
Their target is to *remain rejected* unless the threshold is
met; closure is not the success state. A scope guard that's
never revisited is a scope guard that worked.

The threshold for revisiting any scope guard requires all
three of:

1. **Concrete demonstration that one of the original
   rejection's load-bearing premises no longer holds.**
   Premise abstractions ("what if X changes?") do not
   qualify; specific demonstrations against named premises do.
2. **Named alternative not considered in the original
   rejection.** Re-proposing the same alternative the
   rejection already considered is conjectural; surfacing
   an alternative the rejection did not consider is
   substantive.
3. **At least one specific use case the current design
   fails to serve.** The use case must be concrete and
   documentable; "users might want X" without an instance
   does not qualify.

Revisit absent any one of these is rejected as conjectural
and the scope guard stands.

#### 10.6.1 Eighth-trait proposals beyond Phase 2b (target: remain rejected unless threshold met)

*Description.* The §1.5 criteria for trait identity govern
trait-existence proposals. Once Phase 2b's `StakeEngine`
lands as the eighth trait (per §10.5.1), subsequent
trait-existence proposals (a hypothetical
`ArchivalEngine` at V3.x; a `MultisigEngine`,
`AnonymityNetworkEngine`, or other) must clear §1.5's three
clauses. This entry exists to remember that the rejection
of *speculative* trait additions is a recurring discipline,
not a one-time decision.

*Original rejection.* §1.5 trait-identity criteria; §2.7
consumer-driven justification rule.

*Revisit threshold.* (1) Concrete demonstration that the
proposed trait owns Stage 4 actor state distinct from any
existing trait, has independent failure-isolation domain,
and either has named cross-cutting consumers or has an
explicit lifecycle that bundling into a consumer would
conflate; (2) named alternative not considered (e.g., "this
work belongs as method extensions on existing traits X and
Y" is the typical alternative to consider); (3) at least
one specific operational scenario the current
seven-or-eight-trait design fails to serve. Revisit absent
any one of these is rejected as conjectural.

#### 10.6.2 Trait-level observability re-litigation (target: remain rejected unless threshold met)

*Description.* §3.5 rejects trait-level observability hooks
in favor of `tracing`-at-call-sites. The rejection's
load-bearing premises are: (a) the wallet's observability of
its own state is already adequate via existing read methods;
(b) trait-level observability invites scope drift the §1.4
actor-shape discipline cannot easily evaluate. This entry
exists to remember that the rejection has named premises
that future contributors may attempt to revisit.

*Original rejection.* §3.5 observability-via-tracing
rejection; §1.5 scope-guard meta-pattern enumeration.

*Revisit threshold.* (1) Concrete demonstration that one of
§3.5's premises no longer holds — e.g., a specific class of
operation that genuinely cannot be served by tracing at
call sites and that requires trait-level introspection;
(2) named alternative not considered in §3.5 (the §3.5
rejection considered tracing spans, in-band progress
channels per §2.3, and chain-RPC for network-wide
observability — alternatives outside this set may be
substantive); (3) at least one specific use case the
tracing-at-call-sites pattern fails to serve, with the
failure mode named operationally rather than abstractly.
Revisit absent any one of these is rejected as conjectural.

#### 10.6.3 Consensus-rule enforcement re-litigation (target: remain rejected unless threshold met)

*Description.* §2.7's consensus-as-truth scope guard rejects
wallet-side enforcement of consensus rules (e.g., "stakers
must archive," activation thresholds, slashing conditions).
The rejection's load-bearing premises are:
(a) cryptocurrency-correctness — wallet-side enforcement is
meaningless because alternative wallets won't enforce it
and the chain accepts whatever consensus accepts;
(b) scope-discipline — `EconomicsEngine`'s charter is
canonical derivation, not orchestration;
(c) bug-class prevention — wallet-side enforcement creates
an attack surface that the chain layer is designed to
absorb. This entry exists to remember that the rejection
has named premises that future contributors may attempt to
revisit (the orchestrator-framing pattern recurred twice
during Round 3 and Round 4a; future iterations are
expected).

*Original rejection.* §2.7 consensus-as-truth pin (Round 4a
Item 3); §2.7 `EconomicsEngine` scope guard (Round 4a
Item 19); §1.5 scope-guard meta-pattern enumeration.

*Revisit threshold.* (1) Concrete demonstration that one of
§2.7's three premises no longer holds — e.g., a consensus
mechanism where wallet-side enforcement is genuinely
meaningful (such mechanisms are vanishingly rare in
cryptocurrency design); (2) named alternative not
considered in §2.7 (the §2.7 rejection considered
chain-side enforcement, economic incentivization, and
hybrid mechanisms — alternatives outside this set may be
substantive); (3) at least one specific use case the
consensus-as-truth model fails to serve, with the failure
mode named at consensus-protocol level rather than at
client-convenience level. Revisit absent any one of these
is rejected as conjectural.

#### 10.6.4 Deployment-configuration pinning re-litigation (target: remain rejected unless threshold met)

*Description.* Four properties of the deployment context — the
host process's allocator, TLS implementation, tokio runtime
configuration, and panic strategy — are governed by binary-level
build configuration and operator-tuned runtime settings, not by
the wallet engine's trait surface (per §10.1.3's fifth bullet).
The spec does not pin defaults for these; deployment-level
review (and the build/run-time configuration) governs them. This
entry exists to remember that future contributors may attempt to
pin one of these in the spec (e.g., "the wallet shall use
jemalloc"; "the wallet shall use rustls"; "the wallet shall
configure tokio with N worker threads"; "the wallet shall be
built with `panic=abort`"); the rejection of speculative
spec-level pinning is a recurring discipline.

*Spec-indifferent vs spec-dependent properties.* Three of the
four (allocator, TLS, tokio runtime config) are
**spec-indifferent**: the trait surface and §7 invariants do
not change behavior depending on which choice the binary makes.
The fourth — **panic strategy** — is **spec-dependent**:
§5.1's supervisor design assumes `panic=unwind` so that
`PanickedDuringHandler` semantics are observable (under
`panic=abort` the process terminates instead of unwinding into
the supervisor, which means the `RuntimeFailure` variant
distinction §5.2's retry contract relies on cannot be produced
at all). The spec names the assumption explicitly here so that
binaries built with `panic=abort` are *known to be out of
contract* for the §5.1 supervisor mechanism — the spec does not
enforce the build configuration, but it does name the
configuration the spec depends on. Future contributors who
configure `panic=abort` should expect §5.1's
`PanickedDuringHandler` path to be unreachable; the existence of
this dependency is documented rather than discovered late at
Stage 4 cutover.

*Original rejection.* §10.1.3 fifth bullet
(deployment-context-properties exclusion); §1.5 scope-guard
meta-pattern enumeration.

*Revisit threshold.* (1) Concrete demonstration that a deployment
property's choice has *trait-surface* consequences not yet
captured in the spec — i.e., the property is no longer
deployment-context-only because some trait method's documented
behavior depends on it; (2) named alternative not considered
(e.g., "the trait surface should expose an allocator
configuration parameter" must consider whether the same
parameter could be passed at binary configuration level
instead); (3) at least one specific scenario where the
unconstrained-by-spec status causes a concrete operational
failure that pinning a default would prevent, with the failure
mode named operationally rather than abstractly. The
panic-strategy entry is partially closed by the
spec-dependent-assumption pin above (the dependency is
documented; what remains open is whether to *enforce* it via
`build.rs` checks or `Cargo.toml` profile settings); a revisit
of the panic-strategy property argues for enforcement, not
re-pinning of the assumption itself. Revisit absent any one of
the threshold conditions is rejected as conjectural.

---

## Cross-references

- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine architecture: actor model with staged migration from composition"* (2026-04-27) — the architectural commitment this spec realizes.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Engine binary boundary: pure message-passing over shared handle"* (2026-04-27) — Path B, retires the outer `Arc<RwLock<Engine>>` at Stage 4.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"`RefreshHandle` (Phase 2a Branch 2) ships transitional `Arc<RwLock<Engine>>` under Path B"* (2026-04-27) — explicit pin that the current self-arc is transitional.
- [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) §*"Pending-tx protocol: two-phase build/submit/discard over single-phase callback"* (2026-04-27) — the `PendingTxEngine` surface.
- [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs) `run_refresh_task` rustdoc — the cancellation contract reproduced inline (PR 4 Phase 1 brings the inline rustdoc into alignment with §7's five-checkpoint discipline).
- [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs) `Engine::refresh` rustdoc (post-2026-04-28) — the sync-vs-async cancellation split.
- [`rust/shekyl-engine-core/src/engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs) — current `MockDaemon` (renamed from `MockRpc` in Stage 1 PR 1, extended into a full `DaemonEngine` implementor with submit dedup, fixed fee-estimate snapshot with override hook, and queued-error injection per §6.1; `ChaCha20Rng` reserved for future fee-jitter / synthetic-fork randomization per §6.2 but not yet consumed at this PR's contract surface) and `make_synthetic_block` scaffolding; `derive_seed` helper per §6.2.
- [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) "Generic `DaemonClient`" — closed: spec by §2.5 (two-trait shape); Stage 1 implementation by PR 1 (§2.5 surface + `Engine<S, D>` parameterization + first hybrid test); production-constructor generalization deferred to V3.2 alongside the `DaemonEngine`-to-`pub` promotion.
- [`docs/CI_BASELINE.md`](CI_BASELINE.md) — `shekyl-oxide` divergence-canary policy referenced in §2.5's upstream/downstream rationale.
- [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc) — the "4–6 review rounds before any Rust" rule this document is run against.
- [PR #20](https://github.com/Shekyl-Foundation/shekyl-core/pull/20) — the spec's review-and-acceptance PR (merged 2026-05-01, merge commit `40093ac7a`; Interpretation D: linear-append commits per round, Rounds 1–5).
