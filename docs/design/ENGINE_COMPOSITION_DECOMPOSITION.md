# Engine composition: making it less of a monolith

**Status:** LIVING CONTRACT. Last verified 2026-09-03 (StakeFacade product door + crate-wide `METHODS_CEILING` count freeze). Landing inventory: [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).

| Field | Value |
|-------|--------|
| **Date** | 2026-07-19 (StakeFacade + inherent-API freeze: 2026-09-02; crate-wide walk: 2026-09-03) |
| **Context** | Follow-up to `WALLET_DAEMON_HOSTILE_AUDIT_2026-07-19.md` — finding that `Engine` remains a large composition hub despite Stage 1 traits and Stage 2 actors |
| **Audience** | Wallet rewrite owners deciding how to decompose without fighting the staged actor migration |

---

## What “monolith” still means here

It is not “you forgot modules.” Looking at the tree:

| Already modular | Still concentrates on `Engine` |
|-----------------|--------------------------------|
| 7 Stage‑1 traits | Composition root with **7 type params + ~15 fields** |
| `KeyActor` / `CurveTreeActor` | **Inherent API surface** for almost every user action |
| Local* implementors | **Cross-domain orchestration** (refresh ↔ merge ↔ pending ↔ submit ↔ stake ↔ pscan) |
| File / prefs / units crates | **God-files**: `local_pending_tx` ~5.4k, `stake_engine` ~4.6k, `refresh` ~4.3k, `lifecycle` ~2.6k |

So modularization moved **implementation** out; **identity, wiring, and workflow ownership** stayed on `Engine`. That is normal at Stage 1–2. The next step is not “`Engine<8,9,10 params>`” — it is **stop treating Engine as the place workflows live**.

In-tree docs already point the right direction: Stage 1 traits for swap, Stage 4 actors; `StakeEngine` called out as a later trait. The recommendation below goes slightly further than “add StakeEngine” and splits **orchestration** from **capabilities**.

---

## Target shape: thin shell + capability bag + workflow services

```text
┌─────────────────────────────────────────────────────────┐
│  Engine  (thin shell: lifecycle + capability bag)       │
│  open / close / password / network / capability         │
│  holds Caps { key, ledger, daemon, refresh, pending,    │
│               persist, economics, tree, stake?, pscan? }│
└───────────────────────────┬─────────────────────────────┘
                            │ passes Caps (or subsets)
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   TransferWorkflow    StakeWorkflow      ScanSupervisor
   build→sign→submit   bond/claim/drain   refresh + merge
        │                   │                   │
        └──────── uses trait surfaces only ─────┘
```

**Rule:** `Engine` may **own** subsystems and **expose** a small stable façade. It should **not** implement multi-step money/staking/scan protocols as inherent methods on the type-parameter monster.

That matches what was already done for keys (actor owns secrets; orchestrator holds a handle) — apply the same idea to **workflows**, not only secrets.

---

## Concrete moves (ordered, low thrash)

### 1. Freeze the trait count; don’t grow `Engine<…>` further

Seven generics is already painful (`P`’s default alone is a paragraph). More parameters make the monolith *worse* for humans even if “more modular” on paper.

Prefer:

- **Fixed production type aliases** at the crate edge  
  `type SoloEngine = Engine<SoloSigner, DaemonClient, LocalLedger, …>;`
- New domains as **owned services**, not new type parameters, until Stage 4 forces a handle:

```rust
// Conceptual — not a ship-tonight proposal
struct Caps {
    key: KeyEngineHandle,
    ledger: Arc<dyn /* or concrete L */>,
    daemon: D,
    tree: CurveTreeHandle,
    pending: P,
    // …
}

struct TransferService<C> { caps: C }
impl TransferService<C> {
    async fn build(...) -> Result<ReservationId, SendError> { ... }
    async fn submit(...) -> Result<..., ...> { ... }
}
```

Production `Engine` holds `TransferService` (or builds it on demand from fields). Tests construct `TransferService` with a smaller `Caps` subset — **no need to construct a full Engine** for pending-tx tests.

Sharing `Arc<L>` between ledger and pending is already the right pattern. Push it until **workflows never name `Engine`**.

### 2. Split by *workflow*, not by noun

Trait nouns (Key, Ledger, Daemon) are good **capability** cuts. Monolith pain lives in **pipelines** that touch many nouns:

| Workflow | Owns today (approx.) | Extract to |
|----------|----------------------|------------|
| **Open/close** | `lifecycle.rs` | Keep on Engine (true shell duty) |
| **Refresh → merge → indexes** | `refresh.rs` + `merge.rs` + LocalRefresh | `ScanPipeline` / keep under Refresh supervisor only |
| **Select → assemble → sign → reserve → submit → watchdog** | `local_pending_tx` + sign_bridge + submit_* | **`TransferWorkflow`** (highest ROI) |
| **Bond / claim / emission / drain** | `stake_engine` + bond_* + claim_* + emission_* | **`StakeWorkflow`** (planned StakeEngine, but as workflow + trait) |
| **P-scan / accrual / pending-post** | `pscan/*` | **`PScanSupervisor`** (already half-isolated; stop routing through Engine inherent soup) |

**Highest ROI:** carve `local_pending_tx.rs` into a `transfer` module tree *without* changing the trait surface yet:

```text
engine/transfer/
  build.rs          // selection + reservation
  assemble.rs       // already partly signing_assembly
  sign.rs           // sign_bridge glue
  submit.rs         // submit_lifecycle + watchdog hooks
  fingerprint.rs
  error.rs          // SendError lives nearby
  mod.rs            // TransferWorkflow
```

Same code, new ownership. `Engine::build_pending_tx` becomes a one-liner delegate. Review blast radius collapses.

Do the same for `stake_engine.rs` next (bond assemble / claim / emission are already separate files — the **orchestrator** is the blob).

### 3. Capability facets at the API, not one mega-Engine

Today callers think in `engine.everything()`. Prefer façade objects that only expose what they can do:

```rust
impl SoloEngine {
    pub fn transfer(&self) -> TransferFacade<'_> { ... }
    pub fn stake(&self) -> StakeFacade<'_> { ... }  // always a view; has_stake_engine() is the handle predicate
    pub fn scan(&self) -> ScanFacade<'_> { ... }
    pub fn account(&self) -> AccountFacade<'_> { ... }     // address, capability, network
}
```

Benefits:

- **Compile-time and review-time scoping** — stake code cannot casually call transfer-only helpers if they’re not on the facet (or only via shared Caps traits).
- RPC/CLI map cleanly: wallet-rpc “send” only takes `TransferFacade`.
- Matches capability reality (`can_spend_locally`, view-only stubs) better than dumping methods on `Engine`.

Under the hood still one process, one ledger lock discipline — facets are **views**, not separate processes (until Stage 4).

### 4. Formalize the “Caps” / context object (kills cross-talk)

The recurring anti-pattern in large engines is methods that take `&self` and reach for five fields. Replace with **explicit context structs per workflow**:

```rust
pub(crate) struct TransferCtx<'a, L, D, Tree, Signer> {
    pub ledger: &'a L,
    pub daemon: &'a D,
    pub tree: &'a Tree,
    pub sign: &'a Signer,      // KeyEngineHandle or LocalSigner
    pub network: Network,
    pub fee: &'a FeeBits,
}
```

Rules:

- Workflow functions take `TransferCtx`, not `Engine`.
- Need a new dependency? **Add a field to the ctx** (reviewable) instead of silently using another `self.foo`.
- This is how you get modularity *before* full actors: data dependencies become visible.

Pieces already exist (`assemble_tx_to_sign` takes parallel arrays, not whole Engine). Finish that migration for the whole send path.

### 5. Separate “long-running supervisors” from “request/response API”

Refresh and pscan are **tasks** with slots, RAII guards, and cancel semantics. Pending submit is a **driver tick**. Those should not share mental model with `primary_address()`.

Suggested ownership:

| Kind | Lives | Engine role |
|------|--------|-------------|
| Supervisors | `ScanSupervisor`, `PScanSupervisor`, `SubmitDriver` | spawn/stop + hold handles/slots |
| Request API | Transfer / Stake / Account façades | sync/async ops, short borrows |
| Shell | `Engine` | open, close, password, prefs, capability, “are supervisors running?” |

`refresh_slot` / `pscan_slot` / `pending_write_lock` / `submit_driver` already look like supervisor state — group them under one `Runtime` or `Supervisors` field so the struct reads as:

```text
Engine {
  identity: network, capability, prefs, persistence,
  caps: Caps { key, ledger, daemon, refresh, pending, economics, tree },
  runtime: Supervisors { refresh_slot, pscan_slot, submit_driver, pending_write_lock },
  stake: Option<StakeEngine>,  // or StakeWorkflow handle
}
```

Even without moving code, **field grouping** makes the composition root scannable.

### 6. Align with Stage 4 instead of fighting it

The planned actor cutover is the right endgame. The intermediate structure should be **actor-shaped without the framework tax**:

| Stage 1–2 (now) | Intermediate (recommended) | Stage 4 |
|-----------------|----------------------------|---------|
| Trait + concrete field on Engine | Trait + **handle/service** owned by Engine | `ActorRef` behind same trait |
| Inherent methods on Engine | Façade → service → trait | Messages to actors |
| God-file implementor | Module tree per workflow | Same modules, message entrypoints |

Do **not** invent a second framework. Do invent **stable trait methods + services that only talk traits**. Stage 4 then swaps `LocalPendingTx` for `PendingTxActor` without rewriting RPC.

### 7. What *not* to do

| Temptation | Why skip |
|------------|----------|
| `Engine` → 10+ type parameters | Unreadable; every call site explodes |
| `Box<dyn Trait>` everywhere “for modularity” | Correctly avoided for Stage 1; keep static dispatch at core |
| One giant “refactor Engine PR” | Will rot; land workflow extract + façade + file split in slices |
| Move ledger off Engine “because monolith” | Ledger *is* the shared state; share `Arc<L>`, don’t clone truth |
| Mock-everything test substrate | No-Mock rule is right; test workflows with real Local* + test daemon |

---

## Transfer workflow ownership (policy)

**Status:** landed structurally (`engine/transfer/`) + ownership pin
(docs + `check_engine_decomposition.sh` tripwire). No separate
`TransferWorkflow` type is required for ownership.

| Claim | Detail |
|-------|--------|
| **The transfer workflow is** | `engine/transfer/` — production type [`LocalPendingTx`], trait [`PendingTxEngine`] |
| **Engine's role** | Owns `pending: P` (default `LocalPendingTx`); may expose **thin** delegates that only call `self.pending.…` |
| **Compat path** | `engine/local_pending_tx.rs` re-exports only — no multi-step bodies |
| **Do not** | Re-inflate select/assemble/sign/reserve/submit/re-anchor logic into `Engine`, `lifecycle.rs`, or a new top-level monofile |
| **Mechanical pin** | `scripts/ci/check_engine_decomposition.sh` §Transfer workflow ownership: `transfer/` must exist; `LocalPendingTx` defined under that tree; shim re-exports from transfer; named orchestration methods must not be *defined* outside `transfer/` |

**Deferred (not blocked on this pin):** a `TransferCtx` struct, `engine.transfer()` façades, renaming `LocalPendingTx` → `TransferWorkflow`. Those are optional API polish once a product surface needs them.

**Tests:** construct `LocalPendingTx` under `transfer/` (see
`engine/transfer/transfer_pending_tx_tests.rs`); do not require `Engine::open` for unit
coverage of the send pipeline.

---

## Stake workflow ownership (policy)

**Status:** landed (`engine/stake_engine/` directory module, per-message-family
carve included) + the decomposition ratchet scans every `engine/` subdirectory.
**Product door (2026-09-02):** [`StakeFacade`](../../rust/shekyl-engine-core/src/engine/stake_facade.rs)
via `Engine::stake() -> StakeFacade<'_>` (always a view, including for
non-stakers). New staking / drain / claim behavior lands on the façade, not as
a new inherent `Engine::` method. Inherent methods that already existed keep
their bodies in the workflow modules; the façade **forwards** so GUI/CLI keep
compiling. Thinning those to one-liners is a later cut, not claimed done.
`unstake` / Unbond dispatch is not a product method yet (`assemble_unbond` is
`pub(crate)`; wallet-RPC `unstake` is RESERVED); when that verb becomes reachable
it lands on `StakeFacade`.

| Claim | Detail |
|-------|--------|
| **The stake workflow is** | `engine/stake_engine/` — `StakeEngine` actor + handle + types + spend helpers |
| **Engine's role** | Owns `Option<StakeEngineHandle>`; exposes `stake()` as the product view. Pre-façade inherent methods (`first_stake`, `stake_in`, `staking_read_view`, drain, `start_*_if_staker`) still hold the bodies (GUI/CLI); `StakeFacade` forwards. Handle predicate is `has_stake_engine()`, not `stake().is_some()` |
| **Layout** | `types.rs` domain values; `helpers.rs` shared funding/vout prep + P-secrets; `actor.rs` the actor struct, spawn, inherent methods and `Actor` impl; `handle.rs` `StakeEngineHandle`; one file per message family (`persona.rs`, `bond.rs`, `claim.rs`, `drain.rs`, `scan.rs`, `retire.rs`); `test_fixtures` + tests EXCLUDE'd |
| **Do not** | Re-inflate bond/claim/drain assembly into top-level monofiles or Engine inherent soup — and do **not** add a `stake_engine/engine.rs`: actor, messages and handle are deliberately three concerns, not one file |
| **Module surface** | `mod.rs` re-exports exactly what `crate::engine::…` consumes. Siblings and the in-tree suite import from siblings directly. No `#[allow(unused_imports)]` on the facade: a re-export that stops being consumed must fail rule 45's gate, which is what keeps the list a true statement |
| **Mechanical pin** | `check_engine_decomposition.sh` FILE / `NEW_FILE_CAP` ceilings still sweep `engine/**/*.rs`; **`METHODS_CEILING`** is a **count** freeze of `pub` inherent methods on `Engine` across `shekyl-engine-core/src` (not only `engine/` — inherent impls can live in `lib.rs` / `scan.rs` / …). Impl-item macros fail closed (this lexer does not expand them). Not a category allowlist — see below |

**Deferred:** renaming to `StakeWorkflow`. Named blocker: call-site rename
across every `stake_handle()` consumer, which is a validation surface of its
own (rule 19) and shares nothing with the file carve. `TransferFacade` /
`engine.scan()` wait until a product surface wants the same cut.

### Inherent `Engine` API — allowed categories

`Engine` may grow **only** in these categories (and each new `pub fn` still
has to fit `METHODS_CEILING`):

1. **Lifecycle** — create / open / close / password.
2. **Capability accessors** — network, capability, address, ledger, prefs, daemon, `has_stake_engine`.
3. **Façade constructors** — `stake()` (and later `transfer()` / `scan()`).
4. **Supervisor start/stop** that is not staking-specific (refresh/rescan).
5. **Pre-freeze inherent names** that already existed (`first_stake`, `stake_in`,
   `staking_read_view*`, drain, `start_*_if_staker`, …). Growing those *bodies*
   with new staking behavior is the reconstitution the freeze does not count.
   New behavior lands on `StakeFacade`. Thinning a pre-freeze method to a
   one-line `self.stake().…` delegate is allowed and does not raise the count.

`METHODS_CEILING` counts methods; it does not encode this list. Adding
`Engine::unstake` while deleting another `pub fn`, or bumping the ceiling in
`engine_decomposition_ratchet.conf`, still compiles against the number. The
allowlist is **review-only**; a new inherent method that is not in categories
1–5 requires both review here and a conf diff. The helper's `--self-test`
(where-clause / `impl Trait for Engine` / `pub(crate)`) runs from
`check_engine_decomposition.sh`.

New staking, fee-policy, or daemon-transport **behavior** does not get a new
inherent method. Put it on `StakeFacade` (or the fee/daemon module, called
through an existing Engine method).

### Rejected hoists (rule 21)

These were considered in the 2026-08-28 state-of-the-code review and
**rejected now**:

- **`shekyl-stake-engine` crate.** No second consumer that cannot use `Engine`.
  Reopen when GUI, a serving-only binary, or economics-sim must link staking
  orchestration without the spend wallet.
- **Stage 1 traits `pub`.** Reopen when a second in-tree crate must construct
  a workflow without `Engine` (not tests). See `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.
- **Hoist `fee_policy` / estimator / snapshot.** Weight already left
  (`shekyl-tx-weight`). Reopen when a second *production* crate needs
  `ValidatedFeeEstimates` without linking engine-core.
- **Move `DaemonClient` into `shekyl-rpc-client`.** The wrapper insulates
  Engine from transport. Reopen if the production type alias hides `D`
  entirely and that insulation job is gone.

---

## Suggested sequence (practical)

1. **Type alias the production engine** so most of the tree never writes the 7-param form.
2. **Group Engine fields** into `identity` / `caps` / `runtime` (structural, low risk).
3. **Extract `transfer/` from `local_pending_tx`**; `Engine` methods become delegates. No behavior change.
   **Done** (`chore/transfer-from-local-pending-tx`): monofile → `engine/transfer/{types,support,engine,trait_impl}.rs` + `engine/transfer/transfer_pending_tx_tests.rs`; thin `local_pending_tx` re-export shim; decomposition ratchet drops the 5420-line baseline and scans `engine/transfer/`.
3b. **Pin transfer workflow ownership** (docs + CI tripwire; no new types).
   **Done** (`chore/transfer-workflow-ownership-pin`): this section + decomposition-check ownership invariants.
4. **Introduce `TransferCtx`** only when a new feature needs it — stop new send-path code from taking `&Engine` as a habit, not as a big-bang rename.
5. **Façade methods** (`engine.transfer()`, `engine.scan()`) for RPC/CLI when those surfaces want a clean cut.
6. **`StakeWorkflow` / StakeEngine** as a real subsystem (optional field), not more inherent methods on Engine.
   **Done** (`chore/ffi-and-engine-size-debt`): monofile → `engine/stake_engine/` as `{types,helpers,actor,handle}.rs` plus one file per message family (`persona`, `bond`, `claim`, `drain`, `scan`, `retire`) + tests/fixtures; the ratchet now sweeps every `engine/` subdirectory rather than a hand-kept list of arms.
   **Done (2026-09-02):** `StakeFacade` + `Engine::stake()` (always a view) + `METHODS_CEILING` count freeze. The `StakeWorkflow` rename stays open (see the ownership section's deferral).
7. **PScan supervisor** already modular — stop growing it via Engine glue; give it a single start/stop API.
8. Only then Stage 4 actor swaps per trait, with services already isolated.

---

## How you’ll know it worked

- `Engine` inherent impl is mostly lifecycle + façades + supervisor start/stop (< ~500 lines of real logic).
- No file under `engine/` > ~1.5–2k lines without a clear single workflow.
- A pending-tx test constructs `TransferService` / `LocalPendingTx` **without** `Engine::open`.
- Adding a stake feature does not require editing `local_pending_tx` or refresh.
- Reviewers can answer “who owns submit verdict state?” with one module name.

---

## Bottom line

Capabilities are modularized (traits, actors for secrets/tree). The monolith left is **orchestration ownership**.

**Fix:** thin `Engine` shell + **workflow services** (`Transfer`, `Stake`, `Scan`) that take an explicit **Caps/Ctx**, not more generics on `Engine`. File-split the god modules first; façades second; Stage 4 actors last.

That is the same architecture already halfway in — finished, instead of “seven traits living inside one brain.”

---

## Related

| Doc | Role |
|-----|------|
| `shekyl-dev/docs/WALLET_DAEMON_HOSTILE_AUDIT_2026-07-19.md` | Full hostile audit (this is a deep-dive on one finding) |
| `shekyl-core/docs/V3_ENGINE_TRAIT_BOUNDARIES.md` | Stage 1 seven-trait contract; Stage 4 actor cutover |
| `shekyl-core/docs/V3_WALLET_DECISION_LOG.md` | Engine architecture staged migration decisions |
| `shekyl-core/rust/shekyl-engine-core/src/engine/mod.rs` | Current `Engine<S, D, L, E, R, P, F>` composition root |

---

## Document control

| | |
|--|--|
| **Location** | `shekyl-core/docs/design/ENGINE_COMPOSITION_DECOMPOSITION.md` |
| **Status** | LIVING CONTRACT (transfer extract + ownership pin + StakeFacade + crate-wide `METHODS_CEILING`; last verified 2026-09-03) |
| **Follow-up** | Optional: `TransferCtx` / `TransferFacade` / `ScanFacade` when product needs them; `StakeWorkflow` rename |
