# V3.1 Multisig — Rust engine integration design

**Status.** **Round 1 OPEN (2026-07-14).** Doc-only design branch
`docs/v31-multisig-rust-engine-plan` off `dev` tip `13bd508c7`. This
document is the **engine-integration** design for V3.1 multisig. It does
**not** re-open the protocol in
[`PQC_MULTISIG.md`](../PQC_MULTISIG.md) (DRAFT v1.1); it maps that
protocol onto the Stage 1 trait surfaces, the `Engine<S:
EngineSignerKind>` dispatch axis, the feature gate, and the C++/Rust
boundary under an explicit **Rust-owns-logic** posture.

**Process.** Follows
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and cites
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
explicitly. Round structure: Round 1 (this doc — load-bearing
questions **MS-1…MS-8**) → Round 2 (R-residuals + Phase 0 binding
forms) → Round 3 (§7.X commit decomposition) → **pre-flight pass
(Round 0 / R0-D#)** → implementation PRs. Per rule 26's halt
condition: **no implementation commits** until design closure **and**
the named pre-flight pass are discharged.

**Trigger fired.**
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§10.3.1: *"V3.1 multisig design phase begins."* This document is that
design phase's engine-integration carrier.

**Identifier family.** **MS-1…MS-N** (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth per
rule 94). Prefix `MS` passes the uniqueness check against
Phase/Stage/M/Bond-PR/SP/SP-T/PR-A/PR-B/PR-E/CT/GF/S/R/F/DQ/SCE/WI/CB/M1.

**Cross-references (binding substrate).**

| Doc | Role |
| --- | --- |
| [`PQC_MULTISIG.md`](../PQC_MULTISIG.md) | Normative protocol (receive, spend, invariants, wire, transport semantics) |
| [`SHEKYL_MULTISIG_WIRE_FORMAT.md`](../SHEKYL_MULTISIG_WIRE_FORMAT.md) | Normative inter-participant envelope bytes |
| [`PQC_MULTISIG_V3_1_ANALYSIS.md`](../PQC_MULTISIG_V3_1_ANALYSIS.md) | Size / attack catalog / cryptographer targets |
| [`MULTISIG_OPERATIONS.md`](../MULTISIG_OPERATIONS.md) | Operator-facing ops guide |
| [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §10.3.1, §2.1, §2.6, §1.5 | Trait-identity + expansion trigger |
| [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](STAGE_1_PR_6_PERSISTENCE_ENGINE.md) §5.4.1 **R6** | Durable-state shape pin (ledger extension; no new persistence trait) |
| [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](STAGE_1_PR_5_PENDING_TX_ENGINE.md) | Pending-tx / `Signer` surface; V3.1 method stubs named |
| [`STAGE_1_PR_4_REFRESH_ENGINE.md`](STAGE_1_PR_4_REFRESH_ENGINE.md) | Refresh / scan consumer pattern |
| [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) | `Engine<SoloSigner \| MultisigSigner<N,K>>` feature-flip posture |
| `rust/shekyl-engine-core/src/engine/signer.rs` | Sealed `EngineSignerKind`; `MultisigSigner` not yet a type |
| `rust/shekyl-engine-core/src/multisig/` (+ `v31/`) | Feature-gated protocol scaffold (incomplete vs protocol §16.1) |

**Hard scope pins (Round 1 opening — not reopenable without named
reversion).**

1. **No production code on this branch.** Documentation and INDEX /
   FOLLOWUPS / CHANGELOG / protocol-plan amendments only until the
   user issues an explicit implementation go-ahead after design
   rounds + pre-flight.
2. **Keep the feature gate.** Default builds remain
   `default = []` without `multisig`. Production packages
   (`shekyl-wallet-rpc`, `shekyl-cli`, GUI FFI consumers) do **not**
   enable the feature until a named flip PR after ship-readiness.
3. **Rust owns multisig logic.** C++ retains only (a) LMDB / chain-DB
   persistence of consensus-visible bytes already written by the
   daemon path, and (b) the existing `scheme_id = 2` verify call into
   Rust FFI. No new `wallet2` scan/validate/construct paths; no new
   multisig logic in `cryptonote_tx_utils.cpp`.
4. **Archival is out of scope.** Multisig is transaction receive +
   spend (+ group setup / transport). No archival-bond coupling in
   this design.

---

## §1 Mission posture

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc):

| Priority | How this design touches it |
| --- | --- |
| **1 — Security** | Primary. Threshold spend authority, DKG secrets, per-output KEM material, honest-signer invariants (§2.7 of the protocol), wipe-on-drop across the engine/FFI boundary (`35` / `36`). Defense-in-depth `group_id` binding at verify is security-load-bearing but consensus-touching — tracked as **MS-8**, not folded into wallet logic. |
| **2 — Privacy** | Primary on the receive path (Option C / Solution C per-output forward privacy; view-tag hints; FA-6b audit gate before load-bearing receive). Spend path must not weaken FCMP++ unlinkability relative to solo. |
| **3 — System longevity** | Feature-gated V3.1 enablement without refactoring V3.0 solo call sites; Stage 4 actor swap-in for any new trait or method surface; V4 FROST-SAL remains a separate feature (`frost-sal-v4` in the protocol plan — not this doc's scope). |

**Three timeframes (rule 05).**

- **Now / V3.1:** ship equal-participants multisig behind the existing
  Cargo feature, wired through Rust engines + FFI.
- **Mining-era end:** threshold custody for treasuries remains
  load-bearing; transport and co-signer models must not assume
  short-lived mining-era ops patterns.
- **V4:** lattice-only signing is a later feature flip; this design
  must not bake classical-only assumptions into durable ledger fields
  or trait method signatures that Stage 4 cannot evolve.

---

## §2 Scope

### §2.1 In scope (this design)

- Map protocol modules onto Stage 1 engines / orchestrator /
  `EngineSignerKind`.
- Decide trait identity (**MS-1**): `MultisigEngine` vs extensions vs
  signer-kind + modules.
- Retire protocol §16.4 C++ wallet/output-construction plans in favor
  of Rust scanner / refresh / tx-builder / KeyEngine paths (**MS-2**).
- Feature-gate discipline and flip criteria (**MS-3**).
- Receive-path placement (**MS-4**), spend-path placement (**MS-5**),
  transport ownership (**MS-6**).
- Confirm / amend Persistence R6 for group + output metadata (**MS-7**).
- Name the daemon `group_id` verify wiring as a separate
  consensus-touching PR (**MS-8**).
- Enumerate Phase 0 binding-form candidates (spec amendments only).
- Register INDEX family and implementation-PR skeleton (Round 3 fills
  commit decomposition).

### §2.2 Out of scope (explicit deferrals)

| Item | Carrier |
| --- | --- |
| Protocol crypto / invariant redesign | [`PQC_MULTISIG.md`](../PQC_MULTISIG.md) (already DRAFT v1.1) |
| Cryptographer review (Phase 6) / external wargame (Phase 5) | FOLLOWUPS V3.1 items; schedule after engine wiring lands enough surface |
| Headless co-signer product | FOLLOWUPS; validates ops model, not engine shape |
| Hardware-wallet multisig | FOLLOWUPS; plugs via `Signer` / KeyEngine actor path |
| GUI / mobile UX | `shekyl-gui-wallet` / mobile plans; consume FFI after flip |
| Archival / staking multisig special cases | Separate design if ever needed |
| V4 `frost-sal-v4` | Protocol §16.7; not V3.1 |
| Enabling `multisig` in release packages | Named flip PR after ship-readiness checklist |

### §2.3 Relationship to existing scaffold

Verified at `dev` = `13bd508c7` (this branch tip):

| Surface | State |
| --- | --- |
| `shekyl-engine-core` feature `multisig` | `default = []`; gates `pub mod multisig` |
| `shekyl-engine-rpc` / `shekyl-ffi` `multisig` | Off by default; handlers / exports `#[cfg(feature = "multisig")]` |
| Production `shekyl-wallet-rpc` / `shekyl-cli` | Do **not** enable `multisig` |
| Envelope capability | `CAPABILITY_RESERVED_MULTISIG` refused at open |
| `EngineSignerKind` / `SoloSigner` | Landed; docs name `MultisigSigner<N,K>` — **type absent** |
| `multisig/v31/` | intent, prover, messages, encryption, invariants, state, heartbeat, counter_proof, group_descriptor + tests |
| Missing vs protocol §16.1 | `construction.rs`, `v31/signing.rs`, `transport/` tree, `tx_counter.rs` (counter lives in state today) |
| `shekyl-crypto-pq::{multisig, multisig_receiving}` | Always compiled (daemon verify + receive primitives) |
| `shekyl-address` multisig address | Landed |
| Daemon `tx_pqc_verify.cpp` | Accepts `scheme_id = 2`; calls `shekyl_pqc_verify` **without** `expected_group_id` |
| `shekyl-scanner` | No multisig-specific scan path yet |
| Protocol §16.4 | Still lists `wallet2` / `cryptonote_tx_utils` — **contradicts MS-2**; Phase 0 amend target |

---

## §3 Pre-flight discipline (template §3 — citation-paying)

### §3.1 Engine identification

- **§10.3.1 binding:** Multisig may be an 8th trait (`MultisigEngine`)
  **or** method extensions on `KeyEngine` + `PendingTxEngine`, subject
  to §1.5 three-condition test. Round 1 **MS-1** decides.
- **Existing surface preserved for V3.0:** `Engine<SoloSigner>` call
  sites must compile without the `multisig` feature. Any additive
  methods are `#[cfg(feature = "multisig")]` or associated items on
  `EngineSignerKind` that only the multisig kind defines.
- **§2.7 consumer-driven justification:** every new trait method names
  its consumer (orchestrator refresh, pending-tx ceremony, RPC/FFI
  handler, GUI via FFI).

### §3.2 Plan-altitude principles (WALLET_REWRITE_PLAN 4–8)

| Principle | Applicability |
| --- | --- |
| **4** architectural-integrity-now | **Applies.** `16` + `20` + `36`: no C++ wallet multisig thickening; secrets stay in Rust engines. |
| **5** closure-rule + audit trail | **Applies.** Round-N inline in this doc; reopen criteria per MS question. |
| **6** pre-execution wider-substrate audit | **Applies.** Pre-flight (Round 0) after Round 3; rule 26 halt condition named in status banner. |
| **7** threat-model anchors | **Applies.** Adversary-controlled daemon (lying fee / tree / hints); malicious cosigner; malicious prover; relay censorship. HW-wallet-as-core is deferred product but shapes `Signer` orthogonality. |
| **8** priority hierarchy | **Applies.** Security/privacy beat shipping a C++ shortcut or ungated feature. |

### §3.3 §8.3 design lenses

| Lens | Disposition at Round 1 open |
| --- | --- |
| **1 Actor-mesh** | **Bounded.** Protocol has multi-party liveness (heartbeat, CounterProof) but Stage 4 actor migration is not required to ship V3.1 behind a feature gate. Revisit if MS-1 chooses a standalone `MultisigEngine` with cross-actor mutation. |
| **2 State-as-collection-membership** | **Deferred to Round 2** if lens 1 upgrades to applies; per-intent state machine is discrete lifecycle (protocol §13). |
| **3 Recursive trust boundary** | **Bounded.** Diagnostics / invariant-violation alerts cross trust boundaries (GUI); no new diagnostic stream trait in Round 1 — reuse Refresh / orchestrator patterns. |

### §3.4 Anti-patterns / inheritance

- **Architectural inheritance:** Monero multisig / `wallet2` multisig
  flows are **not** substrate. Rewrite against `PQC_MULTISIG.md`.
  Protocol §16.4's `wallet2` bullets are inherited-plan drift — delete
  in Phase 0, do not implement.
- **Cost-benefit-defer-to-later:** routing receive/scan through C++
  "because it already parses tx_extra" is rejected under priority 1 +
  rule 20.
- **User-protection defaults in user-absent contexts:** no soft
  compatibility with ungated simple-mode; `unsafe-testing-only`
  remains mutually exclusive with release (protocol §16.7) — align
  feature **names** in Phase 0 (**MS-3**).

### §3.5 Branch posture

- Design: `docs/v31-multisig-rust-engine-plan` (this branch) — doc-only.
- Implementation: short-lived `feat/ms-*` branches off post-closure
  `dev`, each ≤5 working days / ≤10 commits unless a named rule-07
  exception applies (expected: only **MS-8** group_id consensus
  wiring might argue; flag decomposition likely exists → split).

### §3.6 Conformance lenses (CL-1…CL-7)

Deferred to Round 2 once **MS-1** picks the trait surface. Round 1
records the obligation: whichever surface lands must pay CL-1…CL-7
in the Phase 0 amend to `V3_ENGINE_TRAIT_BOUNDARIES.md`.

---

## §4 Phase 0 candidates (pre-enumeration — not locked)

Each candidate is a **doc-only** amend after Round 1–2 close. None
authorize code.

| ID | Target | Intent |
| --- | --- | --- |
| **P0-a** | `PQC_MULTISIG.md` §16.4 / §16.1 / §16.7 | Retire C++ wallet/tx_utils/griefing-RPC bullets; retarget receive/construct to Rust engines; align feature name `multisig` (code) vs `multisig-v3.1` (doc); list missing modules as engine-PR work |
| **P0-b** | `V3_ENGINE_TRAIT_BOUNDARIES.md` §10.3.1 + §2.X | Record MS-1 disposition; add method signatures or `MultisigEngine` §2.X subsection; §8.2 co-landing if surface amends |
| **P0-c** | `WALLET_REWRITE_PLAN.md` Multisig bullets | Replace "feature flip" aspiration with pointer to this doc's ship checklist |
| **P0-d** | Persistence / ledger schema notes | Confirm R6: group descriptor + `tx_counter` + `PersistedMultisigOutput` as `WalletLedger` extension fields (version bump named) |
| **P0-e** | `IMPLEMENTATION_INDEX.md` | Status rows for MS implementation PRs once Round 3 names them |
| **P0-f** | FA-6b / spend-path audit FOLLOWUPS | Re-home target versions explicitly under V3.1 engine ship gate |

---

## §5 Load-bearing questions (Round 1)

### §5.0 Framing

The protocol answers *what* multisig does. Round 1 answers *where it
lives in the Rust wallet stack* and *what must never move to C++*.
Criteria for each MS disposition (template pattern):

1. Threat-model delivery (secrets, invariants, daemon adversarial).
2. Stage 1 / Stage 4 trait integrity (§1.5 / CL-5).
3. Feature-gate isolation (V3.0 builds untouched).
4. Reviewability / rule 19 validation-surface bundling.
5. Reopening criteria (rule 21 shape).

---

### MS-1 — Trait identity

**Question.** Does V3.1 multisig clear §1.5 as an 8th trait
(`MultisigEngine`), or does it live as (a) `EngineSignerKind =
MultisigSigner<N,K>` + feature-gated modules, and/or (b) additive
methods on `KeyEngine` / `PendingTxEngine` / `RefreshEngine`?

**Substrate.**

- §10.3.1 explicitly leaves this open.
- `signer.rs` already seals the solo/multisig dispatch axis and
  documents `MultisigSigner<N,K>` as the V3.1 kind — but the type
  does not exist yet.
- Persistence R6 argued durable state rides `WalletLedger`, not a
  new persistence trait.
- Protocol state (intents, heartbeats, transport) is substantial and
  multi-party — closer to `StakeEngine`'s "isolatable subsystem with
  explicit lifecycle" than to a pure KeyEngine method.

**Candidate shapes.**

| ID | Shape | Sketch |
| --- | --- | --- |
| **MS-1(a)** | `MultisigEngine` 8th trait | Owns group lifecycle, intent state machine, transport hooks; KeyEngine remains secret holder; PendingTx consumes ceremony outputs |
| **MS-1(b)** | No new trait | `MultisigSigner` + `cfg(multisig)` modules; extend PendingTx/Refresh/Key methods only |
| **MS-1(c)** | Hybrid | `MultisigSigner` for spend dispatch + narrow `MultisigEngine` for group/intent/transport only |

**Proposed disposition (OPEN — awaiting Round 1 review).** Lean
**MS-1(c)**: the sealed signer kind is already the rewrite plan's
dispatch contract; a narrow engine clears §1.5 for group/intent
lifecycle without forcing every KeyEngine implementor to grow
multisig methods. Reject **MS-1(b)** if Round 1 wargaming shows
intent/transport state mutating across orchestrator actors without a
named owner (lens 1 upgrade).

**Reopen.** Substrate change showing §1.5 fails for a standalone
engine (no distinct failure domain) → fall back to MS-1(b) with
documented ownership in `Engine` inherent methods.

---

### MS-2 — C++ / Rust boundary (Rust-owns-logic)

**Question.** What is the complete allowed C++ surface for multisig?

**Proposed disposition (OPEN — strong lean, matches product rule).**

| Allowed in C++ | Forbidden in C++ |
| --- | --- |
| Persist consensus-visible tx bytes already on the wire into LMDB / blockchain DB | `wallet2` multisig scan, receive-time validation, griefing scores |
| Call existing / amended Rust FFI verify for `scheme_id = 2` | Multisig output construction in `cryptonote_tx_utils` |
| Mechanical marshaling only | New multisig RPC business logic in `core_rpc_server` beyond exposing bytes already required for solo |

**Phase 0 consequence:** P0-a deletes protocol §16.4's three C++
bullets (or rewrites them as "daemon verify FFI only").

**Griefing scores / `get_griefing_stats`.** Protocol §7.6 is
wallet-scanner policy. If network-wide stats are ever desired, they
are a **Rust wallet-rpc / research tool** concern, not a consensus
daemon feature in V3.1. Round 2 names the deferral.

**Reopen.** Only if a consensus rule requires daemon-side multisig
*policy* beyond signature verify (not expected; protocol claims
"Consensus impact: None").

---

### MS-3 — Feature gate and flip criteria

**Question.** Keep code feature name `multisig` or rename to
`multisig-v3.1`? When may release packages enable it?

**Proposed disposition (OPEN).**

- **Keep Cargo feature name `multisig`** (already wired across
  engine-core / rpc / ffi / fcmp). Phase 0 amends protocol §16.7 to
  match code; do not churn every `Cargo.toml`.
- **Flip criteria (ship checklist — Round 3 refines):**
  1. Round 1–3 closed + pre-flight recorded.
  2. Receive + spend paths land behind the feature with KATs /
     regtest spend gate (PR #193 residue).
  3. FA-6b disposed (audit or explicit waiver).
  4. Envelope capability un-reserved only in the flip PR.
  5. CI proves default/release builds contain no simple-mode symbols
     and do not enable `multisig` until the flip PR.
- **`unsafe-testing-only`:** remains non-default; mutually exclusive
  with enabling `multisig` in release CI.

**Reopen.** If a second production multisig protocol version must
coexist at the Cargo feature layer (unlikely pre-V4).

---

### MS-4 — Receive path placement

**Question.** Where does `scan_multisig_output_for_participant` /
receive-time validation / griefing scoring run?

**Candidate shapes.**

| ID | Shape |
| --- | --- |
| **MS-4(a)** | Extension of `RefreshEngine` / scanner pipeline (preferred lean) — multisig outputs are another scan arm, like emission reward arms |
| **MS-4(b)** | Methods only on `MultisigEngine`, invoked from refresh orchestrator |
| **MS-4(c)** | Standalone RPC-driven scan (rejected lean — breaks unified refresh) |

**Proposed disposition (OPEN).** **MS-4(a)** with optional thin
helpers on MS-1's engine for group-key material access. Persisted
output metadata follows R6 → ledger. FA-6b remains a gate before
declaring receive production-load-bearing.

**Reopen.** If scan cost / griefing policy needs an isolated failure
domain that would poison solo refresh (then MS-4(b) with supervised
isolation).

---

### MS-5 — Spend path placement

**Question.** How do intent → canonical construction → prover →
signature shares → assembly map onto PendingTx / Signer /
MultisigSigner?

**Substrate gaps.** No `construction.rs`; no `MultisigSigner`; FROST
path in `frost_sal` / engine `signer.rs` not daemon-accepted for
multisig; PR #193 residue: input ordering + change destination audit.

**Candidate shapes.**

| ID | Shape |
| --- | --- |
| **MS-5(a)** | `PendingTxEngine` multi-round ceremony API + `MultisigSigner` associated ceremony types (lean) |
| **MS-5(b)** | Entire ceremony inside `MultisigEngine`; PendingTx only submits final bytes |
| **MS-5(c)** | Parallel pending-tx type (`MultisigPendingTx`) selected by `EngineSignerKind` |

**Proposed disposition (OPEN).** Prefer **MS-5(a)** or **MS-5(c)**
after MS-1 settles — both preserve "PendingTx owns build/submit
lifecycle." Round 2 pins the method signatures and the regtest
acceptance gate as a named implementation PR.

**Reopen.** If deterministic construction cannot share solo's
`encode_final_tx` without violating invariant I6 (signing payload
disagreement) — then MS-5(b) with an explicit byte-ownership audit.

---

### MS-6 — Transport ownership

**Question.** Who owns file / relay / nostr / p2p transport: engine
trait, RPC orchestrator, or embedder (GUI)?

**Proposed disposition (OPEN).**

- **Wire format + encrypt/sign envelope:** engine-core `multisig/v31`
  (already partially present) — pure functions + state updates.
- **I/O (filesystem, network):** embedder / RPC adapters implementing
  a narrow `MultisigTransport` trait (or callback surface) injected
  at engine construction — **not** hard-coded nostr/p2p inside
  `shekyl-engine-core` for V3.1.
- **File transport first** (ops guide + GUI scaffolding already
  assume it); relay directory enforcement is policy in the adapter.

**Reopen.** If air-gap file transport requires durable engine-owned
queues that break R6 (then name a ledger field or reject and keep
blobs user-path-only per R6 table).

---

### MS-7 — Persistence (confirm R6)

**Question.** Does anything in the equal-participants protocol
falsify Persistence R6 (§5.4.1)?

**Proposed disposition (OPEN — confirm).** R6 still holds:

- Group setup + acknowledgments + `tx_counter` + per-output
  `PersistedMultisigOutput` → `WalletLedger` extension +
  `save_state`.
- Signing shares / FROST round state → session-scoped, not
  cross-restart.
- File-transport blobs → user paths, not wallet pair.

**Named watch.** `tx_counter` increments that must fsync before
emitting signing material (R6 trigger 2 / R9 credential
availability). Round 2 must either (i) confirm orchestrator can
`save_state` mid-ceremony with cached wrap keys, or (ii) fire the
R6 reversion and amend PersistenceEngine.

**Reopen.** Exact R6 triggers already named in PR 6 §5.4.1.

---

### MS-8 — Daemon `group_id` verify wiring

**Question.** Is wiring `shekyl_pqc_verify_with_group_id` into
`tx_pqc_verify.cpp` part of this engine design or a separate
consensus-touching PR?

**Proposed disposition (OPEN).** **Separate PR**, tracked here as a
ship-gate dependency, not as wallet-engine scope.

- Exists today: FFI `shekyl_pqc_verify_with_group_id`; daemon calls
  `shekyl_pqc_verify` (no group binding).
- Consensus-affecting defense-in-depth; needs its own review cycle
  (FOLLOWUPS already lists it).
- Engine design assumes verify *can* bind `group_id` before flip;
  wallets must not rely on unbound verify for safety properties the
  protocol attributes to group binding.

**Reopen.** If Round 1 concludes unbound verify makes honest-signer
invariants vacuous on-chain — then MS-8 becomes a hard predecessor
of any feature flip (still separate PR).

---

## §6 Round 1 disposition status

| ID | Status | Lean |
| --- | --- | --- |
| MS-1 | **OPEN** | Hybrid (c): `MultisigSigner` + narrow `MultisigEngine` |
| MS-2 | **OPEN** | Rust-owns-logic; C++ = LMDB + verify FFI only |
| MS-3 | **OPEN** | Keep feature name `multisig`; flip checklist |
| MS-4 | **OPEN** | Refresh/scanner arm (a) |
| MS-5 | **OPEN** | PendingTx ceremony + MultisigSigner (a/c) |
| MS-6 | **OPEN** | Pure wire in engine; I/O via transport adapter |
| MS-7 | **OPEN** | Confirm R6; watch `tx_counter` fsync |
| MS-8 | **OPEN** | Separate consensus PR; ship-gate dependency |

**Round 1 closure criteria (not yet met).**

- [ ] Adversarial review of MS-1…MS-8 leans (this segment).
- [ ] Lens-1 applicability re-tested after MS-1 pick.
- [ ] R-residuals named with Round 2 segment pointers.
- [ ] Explicit reopen criteria recorded (per-question above).
- [ ] User / maintainer sign-off that Round 1 may close.

**R-residuals foreshadowed for Round 2 (non-exhaustive).**

- R-A: Exact `MultisigEngine` method surface + CL-1…CL-7.
- R-B: Construction module contract vs `shekyl-tx-builder`.
- R-C: Regtest multisig spend gate contents (ordering, change dest).
- R-D: FA-6b audit vs waiver.
- R-E: Capability bit un-reserve mechanics in flip PR.
- R-F: Griefing-score storage location (ledger vs prefs vs memory).
- R-G: MS-8 sequencing relative to flip.

---

## §7 Implementation gate (no code yet)

Per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):

1. Close Round 1 (this §6 checklist).
2. Round 2: dispose R-A…R-G; lock Phase 0 binding forms P0-a…P0-f;
   land Phase 0 doc amends on the design branch (or a short follow-on
   docs PR).
3. Round 3: §7.X commit / PR decomposition (expected validation
   surfaces: protocol-module completion; receive/scanner; spend/
   MultisigSigner; transport adapter + FFI/RPC; persistence schema;
   flip PR; MS-8 parallel).
4. **Pre-flight pass (Round 0 / R0-D#):** substrate re-check at audit
   pin; confirm feature-default tree; confirm no C++ wallet multisig
   callers; run any prescribed grep/KAT gates from Round 3.
5. **Only then** cut `feat/ms-*` implementation branches — and only
   after explicit user go-ahead.

Until step 5, this repository change set is documentation only.

---

## §8 Appendix — Substrate grep pins (Round 1 open)

Recorded 2026-07-14 against branch tip `13bd508c7`:

```text
# Feature defaults
shekyl-engine-core/Cargo.toml: default = []; multisig = [...]
shekyl-engine-rpc/Cargo.toml:  default = []; multisig = [...]
shekyl-ffi/Cargo.toml:         default = []; multisig = [...]

# Gate
shekyl-engine-core/src/lib.rs: #[cfg(feature = "multisig")] pub mod multisig;

# Signer kind (MultisigSigner absent)
shekyl-engine-core/src/engine/signer.rs: EngineSignerKind + SoloSigner only

# Daemon verify (no group_id)
src/cryptonote_core/tx_pqc_verify.cpp: shekyl_pqc_verify(...) for MULTISIG

# Protocol plan drift
docs/PQC_MULTISIG.md §16.4: wallet2 / cryptonote_tx_utils / get_griefing_stats
```

---

## §9 Document history

| Date | Event |
| --- | --- |
| 2026-07-14 | Round 1 opened on `docs/v31-multisig-rust-engine-plan`; MS-1…MS-8 posed; no dispositions closed |
