# Stage 1 PR 6 — `PersistenceEngine` extraction — design

**Status.** **Design open — Round 1 closed (2026-05-27); Round 2 not
started.** Opened on `dev` tip `b9c03dc24` (post–PR #81 `PendingTxEngine`
merge). This document follows
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and
[`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc).
**Implementation is out of scope until Round 3 closes** — lands on
`feat/stage-1-pr6-persistence-engine` after the §6 readiness gate.

**Round 1 closure pin (2026-05-27).** Load-bearing question disposed:
**F5(b)** — minimum derived keys at trait surface (§5.9); R9 **not**
deferred to Round 2. Steady-state: `save_state(&StateWrapKey, …)` +
`save_prefs(&PrefsHmacKey, …)`; `rotate_password` keeps `Credentials`.
**R10** (`PersistenceError`), **R6** (multisig), **R11** (M1 MFA) pinned
in Round 1. Lens 1 **bounded** at trait surface (§5.0).

**Substrate amendment (post–Round 1, pre–Round 2 close).**
[`WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md`](WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md)
ratified per-region HKDF wrap keys (`wrap_key_region_1`, `wrap_key_region_2`).
§5.9 narrative updated below: **`StateWrapKey` = `wrap_key_region_2`** — F5(b)
steady-state blast radius is **region-2 (ledger cache) at this rotation**,
not shared-`file_kek` "full wallet." HKDF implementation + KAT regen are
**out of PR 6** (separate commits); PR 6 spec-amends and implements against
the amended prescription.

**Reopen criterion:** quiescence/close-ordering the trait cannot express;
multisig §5.4.1 trigger fires; **or** steady-state trait methods regain
`Credentials`/password parameters (blast-radius regression); **or** a
periodic-flush path requires fresh MFA proof per save (R11 trigger).

**Stage 1 is not complete after this PR.** PR 7 (`EconomicsEngine`)
remains. [`STAGE_1_COMPLETION_AUDIT.md`](STAGE_1_COMPLETION_AUDIT.md) and
the §1 status banner in
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) update
only after **both** PR 6 and PR 7 land.

**Branch (design).** `feat/stage-1-pr6-persistence-engine-design` off `dev`
at `b9c03dc24` — **doc-only** revisions until Phase 0 amends
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.6.
Implementation branch `feat/stage-1-pr6-persistence-engine` cuts the
post–Phase-0 `dev` tip per PR 2 / PR 4 / PR 5 precedent.

**Cross-references.**

- **Spec (binding).**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.6 (`PersistenceEngine` trait surface; Q9.11 closed **no** for
  `load_state` on trait). Round 1 **§8.2 amendment**: three-method shape
  (§5.9) + [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §4.3 /
  [`WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md`](WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md)
  (session-cached `wrap_key_region_2`; `file_kek` transient at open).
- **Per-PR template.**
  [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) — structural
  skeleton for this doc; §8.3 / WALLET_REWRITE_PLAN principles 4–8 cited
  in §3 below.
- **Prior PRs (shape precedent).**
  [`STAGE_1_PR_2_LEDGER_ENGINE.md`](STAGE_1_PR_2_LEDGER_ENGINE.md) (Phase 0
  pins + interior `RwLock`),
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](STAGE_1_PR_4_REFRESH_ENGINE.md) (async
  inline sync body),
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  (§7.X commit decomposition). PR 6 is **narrower** than PR 5: no
  diagnostic stream, no secondary traits, bounded actor-mesh lens.
- **Sequencing.**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §8.1:
  `PersistenceEngine` off critical path; may interleave with PR 7.
  **Spawn graph** (§2.8.3): Persistence Group A at Stage 4 — **do not**
  conflate with PR landing order (§3.5).
- **Wallet rewrite (orchestrator collision).**
  [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) Phase 1 polishes
  `Engine` toward a future public `Wallet` API; PR 6 wires
  `PersistenceEngine` into **`Engine` knowing `Engine::close` consumer
  code is rewrite-fodder** — trait shape is durable (§5.11).
- **RPC / sync flush posture.**
  [`WALLET_RPC_RUST.md`](../WALLET_RPC_RUST.md) (`store`, autosave on
  close; multisig in `AppState` under separate `Mutex`; persistence still
  wallet-file flush). Periodic scan flush is **rewrite-era** requirement
  (wallet2 autosave; mobile-every-block patterns) — drives **R9**.
- **V3.1 multisig (forward-compat, not in-scope).**
  [`PQC_MULTISIG_V3_1_ANALYSIS.md`](../PQC_MULTISIG_V3_1_ANALYSIS.md),
  normative [`PQC_MULTISIG.md`](../PQC_MULTISIG.md) §8.4 (output
  persistence), [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §10.3.1 (multisig extends `KeyEngine` / `PendingTxEngine`; possible
  `MultisigEngine`). Round 1 pins whether §2.6 amendment is
  multisig-safe — §5.4 **R6**.

**Distinction from wallet rewrite.** This PR completes another trait from
§2.6; it does not land rewrite-phase wallet domain work.

Subsequent revisions land each design round **inline** per template §2
and PR 5 precedent. Round 2 disposes R-residuals + finalizes §4 / §6;
Round 3 produces §7.X commit decomposition.

---

## §1 Mission posture

Per [`00-mission.mdc`](../.cursor/rules/00-mission.mdc):

| Priority | How this PR touches it |
|----------|-------------------------|
| **1 — Security** | Open/rotate: Argon2 + `file_kek` unwrap; steady-state: HKDF-derived `wrap_key_region_2` + `prefs_hmac_key` only (§5.9). `Credentials` on `rotate_password` and open path only. Aligns with [`35-secure-memory.mdc`](../.cursor/rules/35-secure-memory.mdc) and [`36-secret-locality.mdc`](../.cursor/rules/36-secret-locality.mdc). |
| **2 — Privacy** | Indirect: persisted ledger/prefs are already encrypted at rest; trait extraction does not change wire/crypto semantics. |
| **3 — System longevity** | **Primary.** Extract `PersistenceEngine` so Stage 4 can swap `WalletFile` for `ActorRef<PersistenceActor>` without re-touching `Engine::close` orchestration. |

**Preserve by name:**

- Q9.11: **no** `load_state` on trait — hydration stays on
  `Engine::create` / `open_*` (§2.8).
- Lifecycle constructors remain inherent on `Engine<S>`; trait = ongoing
  save / rotate / prefs only (§2.8.2).

**Three timeframes:**

- **Now.** Trait boundary for periodic + close-path flush and password
  rotation; session sealing keys on orchestrator (§5.9).
- **V3.1+.** YubiKey / FIDO2 **M1** (cryptographic MFA in open-path
  derivation only; trait steady-state unchanged — §5.9.1).
- **Mining era end.** No effect (wallet-file format is V3.0 concern).
- **V4 lattice.** No effect on trait surface; PQC is in envelope/keys
  layers already specified elsewhere.

---

## §2 Scope

### §2.1 In-scope

1. **`PersistenceEngine` trait** — `engine/traits/persistence.rs` +
   `traits/mod.rs` re-export (`pub(crate)` per §2 preamble).
2. **`WalletFile` implementor** — direct impl per §3.1; interior
   `Mutex<WalletFileState>` per §2.6 Round 3 note (`shekyl-engine-file`).
3. **`Engine` parameterization** — `F: PersistenceEngine = WalletFile`;
   field `file` → `persistence: F`; `change_password` / `close` dispatch
   through `F` where applicable.
4. **§8.2 spec amendment** — three-method shape (§5.9);
   [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §4.3 +
   [`WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md`](WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md)
   cross-refs in C0 (implementation + KAT regen: separate commits).
5. **Tests** — real `WalletFile` + tempfile; **no** `MockPersistence` per
   §6.4 and PR 3 precedent.
6. **Docs** — this design doc, `CHANGELOG.md`, trait rustdoc.

### §2.2 Out-of-scope

| Item | Where |
|------|--------|
| `EconomicsEngine` | PR 7 |
| `KeyEngine` on `Engine<S, …>` | Follow-up; `Arc<AllKeysBlob>` remains per completion audit §3.3 |
| Full §3 reorder `<S, K, L, E, D, F, R, P>` | Chore when `K` + `E` wire; PR 6 appends `F` only |
| Stage 4 actors, spawn timeouts, teardown cascade | §2.8.3–2.8.6 |
| `load_state` / open on trait | Q9.11 closed no |
| `LedgerEngine` persist read accessor (Phase 0c) | Not invented in PR 6 |
| Wallet rewrite Phases 1–5 | `WALLET_REWRITE_PLAN.md` |
| FFI / C++ / `shekyl-engine-rpc` | V3.2+ |
| Diagnostic stream / `FaultInjecting` wrapper | Bounded lens; no failure-injection trait surface at V3.0 |

---

## §3 Pre-flight discipline checklist

**Audit pin:** `dev` at `b9c03dc24` (2026-05-27).

This section pays the **citation cost** for
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) §3 and
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §8.3.

### §3.1 Engine identification (template §3.1)

- [x] **§2.6 binding.**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.6
  — ownership: `WalletFile`, advisory lock, KEK rewrap, atomic writes.
- [x] **§1.5 three-condition test.** Distinct Stage 4 state ownership
  (file handle + lock); distinct failure domain (IO / corrupt / network
  mismatch); isolatable subsystem with explicit lifecycle (open, save,
  rotate, close-with-flush). **Refinement PR** on existing spec surface,
  not additive trait — cite §8.1 row for `PersistenceEngine`.
- [x] **Surface amend vs preserve.** **Amends** §2.6: `save_state` gains
  `credentials: &Credentials<'_>` per §8.2 (Round 1 disposition). All other
  methods preserved; `rotate_password` already uses `Credentials` in spec.

### §3.2 Plan-altitude principles (template §3.2 — `WALLET_REWRITE_PLAN.md`)

| Principle | Applicability |
|-----------|----------------|
| **4 — architectural-integrity-now** | **Always applies.** Governs: direct `WalletFile` impl (no `LocalPersistence` deferral); `Mutex` now for `&self` trait; §8.2 amendment now for `Credentials` on `save_state`. Rules: `16-architectural-inheritance.mdc`, `21-reversion-clause-discipline.mdc`. |
| **5 — closure-rule + audit trail** | **Always applies.** Round 1 **not closed** — reviewer walkthrough; Round 2 segment structure (2a–2g, 2d, 2i); Round 3 → §7.X; reopen criterion in status banner. |
| **6 — wider-substrate audit** | **Applies.** Lands as Round 2 segment **2i** (after 2g close-out) per template §6 — **not started**. |
| **7 — threat-model anchors** | **Applies with narrowing.** Adversary-controlled **daemon** is N/A for persistence IO; wargaming focuses on **memory disclosure** (password caching), **close ordering** (pending tx / refresh vs flush), and **corrupt-prefs** paths already in `WalletFile`. HW-wallet anchor N/A. |
| **8 — priority-hierarchy** | **Applies** to password-cache vs UX trade-off (reject cache = priority 1). No priority-3 feature trade-offs in scope. |

### §3.3 Per-engine-PR disciplines (template §3.3 — §8.3)

| Discipline | Applicability | Citation / PR 6 disposition |
|------------|---------------|------------------------------|
| **§8.3.1 Lens 1 (actor-mesh)** | **Bounded (trait surface)** | Lens implications do **not** propagate to the trait API: no cross-actor liveness queries on `save_state` / `rotate_password`. Close ordering (pending → ledger snapshot → persist) stays on `Engine::close`. Stage 4 mailbox blocking is an **implementor** concern, not a trait-surface concern — §5.0. |
| **§8.3.1 Lens 2 (collection membership)** | **N/A at trait surface** | No per-record lifecycle **on the trait**. Cross-file region consistency under `rotate_password` is an **implementor-internal** invariant — §3.7 row; not a lens-2 state machine. |
| **§8.3.1 Lens 3 (trust boundary / diagnostics)** | **N/A** | No diagnostic-stream seam. |
| **§8.3.2 Anti-patterns** | **Cite at Round 1 / 2** | Cost-benefit-defer (`LocalPersistence`); user-protection-defaults (password cache); MockPersistence; landing vs spawn graph conflation — see §5.6. |
| **§8.3.3 Closure-rule discipline** | **Always** | Status banner + Round 1 §5.7; Round 2 segments TBD; §5.6.9 matrix after segment 2i. |
| **§8.3.4 Process discipline** | **Always** | §7.X after Round 3; simplified C0–C7 shape (no PR-5-scale C2/C4/C7 fault-injection) — rationale in §7.X opening. |
| **§8.3.5 Threat-model anchors** | **Partial** | Daemon anchor N/A; structural anchor = wallet-file spec §4.3 + secure-memory rules. |

### §3.4 Architectural-inheritance audit (template §3.4)

Two substrates — **do not conflate**:

| Substrate | Disposition | Evidence |
|-----------|-------------|----------|
| **Implementor** (`WalletFile` / `shekyl-engine-file`) | **Shekyl-native. Rewrite, not carry.** Post-quantum envelope, capability discriminator, Poly1305 cross-file binding, HMAC prefs — not `wallet2` bytes-on-disk. No Monero path preservation per `60-no-monero-legacy.mdc`. | `shekyl-engine-file` crate; adversarial corpus fixtures. |
| **Trait surface** (`PersistenceEngine`) | **wallet2-*shaped* API, earned by convergent constraints — not inherited.** `save_state` / `save_prefs` / `rotate_password` resemble Monero's persistence calls because single-writer advisory lock + atomic close flush + atomic KEK rotation force the same three-operation surface regardless of on-disk format. A 2027 reviewer asking "why does this look like wallet2?" gets: **constraints converge on this shape**; implementor is unrelated. | WALLET_FILE §4.3 (password every save); §2.8.5 (ledger flush before persistence stops); Q9.11 (hydration off-trait). |
| Audit projection | **Confirmation-shaped** for implementor migration; **trait-surface justification** recorded above (not only implementor row). One production write path at `close` + `rotate_password`. R0-D in §3.6. | PR 3 audit precedent. |

### §3.5 Branch posture (template §3.5)

- [x] [`06-branching.mdc`](../.cursor/rules/06-branching.mdc) rule 2: design
  branch `feat/stage-1-pr6-persistence-engine-design`; implementation
  `feat/stage-1-pr6-persistence-engine`; ≤5 days / ≤10 commits target.
- [x] No push without user authorization.

### §3.6 Substrate enumeration (R0-D — implementation pre-flight pins)

**`WalletFile` / `self.file` call sites** (`shekyl-engine-core` only):

| Site | File:line | Operation |
|------|-----------|-----------|
| Field | `engine/mod.rs:311` | `file: WalletFile` |
| Accessor | `mod.rs:598–599` | `file() -> &WalletFile` |
| Create / open | `lifecycle.rs:467–468, 538–540, …` | `WalletFile::create` / `open` — **not** trait scope |
| Assemble | `lifecycle.rs:668, 713` | Single assembly site |
| Prefs at create | `lifecycle.rs:497–501` | `save_prefs` |
| Change password | `lifecycle.rs:959–961` | `rotate_password` — `WalletFile` is `&mut self` today |
| Close | `lifecycle.rs:1007–1016` | `save_state` + `save_prefs`; `LocalLedger::read()` |
| Error map | `lifecycle.rs:372–385` | `map_wallet_file_error` → rename `map_persistence_error` |

**Trait vs `WalletFile` gaps:**

| Method | Spec §2.6 | `handle.rs` | Gap |
|--------|-----------|-------------|-----|
| `save_state` | `(&self, ledger)` | `(&self, password, ledger)` :480–484 | **Needs `Credentials` in trait** (§8.2) |
| `rotate_password` | `&self` + `Credentials` | `&mut self` :507–512 | **`Mutex` interior mutability** |
| `base_path` | `&Path` | missing | Delegate to `state_path()` (`paths.rs`) |

**`network` / `capability`:** cached on `Engine` at `assemble` from
`file.network()` / `file.capability()` — **keep cache**; single source at
open.

| R0-D | Finding | Disposition |
|------|---------|-------------|
| R0-D1 | `save_state` password | Phase 0a §8.2 amendment |
| R0-D2 | `rotate_password` `&mut self` | C2 `shekyl-engine-file` Mutex |
| R0-D3 | `base_path()` | C2b |
| R0-D4 | No `F` on `Engine` | C4 append `F` |
| R0-D5 | `close` + `LocalLedger` | C5 keep specialization; Phase 0f |
| R0-D6 | No MockPersistence | C6 real `WalletFile` tests |

### §3.7 Trait vs threat model (template §4.1 §3.1)

| Property | Delivery |
|----------|----------|
| Secret-locality at trait surface | Steady-state: `StateWrapKey` (= `wrap_key_region_2` per HKDF amendment) + `PrefsHmacKey`; not `Credentials`. **`file_kek` and `wrap_key_region_1` zeroized after open** per amended §2.6 / HKDF doc §4.1. |
| Session sealing material on orchestrator | `Zeroizing<StateWrapKey>` + `Zeroizing<PrefsHmacKey>` from open through close; password zeroized after open. Steady-state cache leak bounds to **region 2 + prefs integrity**, not spend keys (§5.9). vs F5(a): no cross-account password reuse. |
| Password not cached in `WalletFile` | Implementor receives borrowed sealing keys per call; no password cache in implementor |
| Post-`rotate_password` cache | Orchestrator **must** re-derive `StateWrapKey` / `PrefsHmacKey`; stale handles fail loud (Poly1305) — trait rustdoc pin (Phase 0o / C1) |
| Advisory lock single-writer | `WalletFile` + `KeysFileLock`; **process lifetime** may exceed single `Engine::close` for wallet-RPC daemon (§6.1) |
| Atomic state writes + durability contract | `atomic_write_file`: tmp → fsync(file) → rename → fsync(parent) (`shekyl-engine-file/src/atomic.rs`). Trait rustdoc: **`Ok(())` = durable across power loss** (Phase 0b / C1) |
| Save failure typing | **R10:** `type Error: Into<PersistenceError>` (not `OpenError`; §5.10) |
| Close refuses in-flight pending | Unchanged — `outstanding_pending_txs()` before persist |
| No `load_state` on trait | Q9.11 — construction-only |
| Cross-record consistency under `rotate_password` | **Implementor-internal invariant; not exposed at trait.** Region 1 (`.wallet.keys`) rewrap preserves bytes used as AEAD AAD for region 2; `keys_file_bytes` cache updated so subsequent `save_state` anti-swap binding unchanged (`handle.rs:500–506`). Trait exposes `rotate_password` only; Poly1305 / `state_tag` contract stays inside `WalletFile`. Round 2 **2d** may add rustdoc pin on impl, not new trait methods. |

---

## §4 Phase 0 binding-form candidates

Pre-enumeration for Round 2 close-out finalization. **Amendment commits
doc-only** per §8.2.

| Pin | Binding form | Lands in commit |
|-----|--------------|-----------------|
| **0a** | §2.6 three-method shape: `StateWrapKey` / `PrefsHmacKey` / `Credentials` on rotate only + §4 async rows | **C0** |
| **0a′** | Parent spec §4.3 + HKDF region derivation doc cross-ref in §2.6 / Round 6 note: cache **`wrap_key_region_2`** only; `file_kek` transient at open. **Layout unchanged; no `file_version` bump.** Tier-3 KAT regen when `wallet_envelope` implements HKDF — **not in PR 6 C0.** | **C0** (with 0a) |
| **0o** | Trait rustdoc: `StateWrapKey` = `wrap_key_region_2`; `rotate_password` invalidates cached sealing keys | **C1** |
| **0b** | §2.6: `PersistenceError`; durability rustdoc (`Ok` = power-loss safe) | **C0** |
| **0b′** | §2.6 Round 6 note: minimum-key-at-trait + blast-radius rationale (§5.9 wargame) | **C0** |
| **0c** | Confirm §4 idempotency rows for persistence methods | **C0** (confirm only) |
| **0d** | `Mutex<WalletFileState>` matches §2.6 implementing-type note | **C2a** |
| **0e** | `engine/traits/persistence.rs` + re-export | **C1** |
| **0f** | `close` keeps `Engine<…, LocalLedger, …>` impl until Phase 0c accessor | **C5** |
| **0g** | `Engine<S, D, L, R, P, F = WalletFile>`; field `persistence: F` | **C4** |
| **0h** | `map_persistence_error(WalletFileError, …) -> PersistenceError` | **C3** |
| **0i** | `WalletFile::base_path() -> state_path()` | **C2b** |
| **0j** | Q9.11: no `load_state` on trait | **C0** (doc confirm) |
| **0k** | §6.4: no `MockPersistence` | **C6** |
| **0l** | Stage 4: `ActorRef<PersistenceActor>` same trait | doc only |
| **0m** | R6: §2.6 forward-compatible with V3.1 multisig per §5.4.1; amendment triggers named | **C0** (doc confirm) |
| **0n** | `seal_state_*` uses `wrap_key_region_2` (session-cached or re-HKDF from transient `file_kek` at open only) — no Argon2 per autosave | **C2c** (engine-file / crypto-pq; depends on HKDF impl commit) |

---

## §5 Load-bearing question (Round 1 — closed)

### §5.0 Actor-mesh framing (lens 1 — bounded at trait surface)

Per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §8.3.2,
**PersistenceEngine** lens 1 is **bounded** with explicit scoping:

| Concern | Where it lives | Lens implication |
|---------|----------------|------------------|
| Trait methods (`save_state`, …) | Receive messages; no polling other actors | **Does not apply** — no cross-actor liveness on trait API |
| Close orchestration | `Engine::close`: refuse-if-pending → ledger read → `save_state` | **Orchestrator**, not trait — §2.8.5 teardown graph at Stage 4 |
| Stage 4 sync IO in mailbox | `WalletFile` / `PersistenceActor` implementor | **Implementor** — may block actor; does not change trait shape |
| Stage 4 `stop_gracefully` ordering | Persistence stops after ledger flush (Group B′ → A′) | **Lifecycle** — §2.8.5; Round 2 **2a** / **R8** |

**Bounded** means lens-1 implications **do not propagate to the trait
surface**, not "persistence has no Stage 4 concerns."

**No §5.0 multi-shape wargaming** (contrast PR 5). Trait methods remain
`async fn` wrapping inline sync IO at Stage 1 (PR 4 / `LocalLedger`
precedent). Close-vs-refresh and cancellation safety are **R-residuals**
(R1, R8), not Round 1 reopeners.

### §5.1 The question (reframed — Round 1 reopen)

**What minimum secret material does each `PersistenceEngine` method need at
the trait boundary, and where does that material live between `open` and
`close`?**

Sub-questions (disposed in §5.9):

1. Periodic flush during long sync requires `save_state` **outside** close
   only — without caching the **password** on `Engine`.
2. Trait surface must be **grep-auditable** (typed sub-keys vs ambiguous
   `Credentials` on every save).
3. Shape must survive **V3.1 M1 MFA** (factors in open/rotate only — §5.9.1).

The old framing ("how do we pass `Credentials` at the trait boundary?") is
**withdrawn** — it optimizes the wrong threat model under memory disclosure
(§3.2 principle 7).

### §5.2 Implications for prior PRs

| PR | Interaction |
|----|-------------|
| PR 5 `PendingTxEngine` | `Engine::close` refuses when `outstanding() > 0` — unchanged. Persistence runs after pending check. |
| PR 4 `RefreshEngine` | Round 2 must confirm: at `close`, `self` is consumed — no concurrent `apply_scan_result` on same engine instance. Structural today; document in 2a. |
| PR 2 `LedgerEngine` | `close` uses `LocalLedger::read()` for `&WalletLedger` — specialization retained (Phase 0f). |

### §5.3 Criteria rationale

| # | Criterion | PR 6 application |
|---|-----------|------------------|
| 1 | Stage 4 swap-in | `&self` + `Mutex`; trait stable for `ActorRef` |
| 2 | Testability without Mock | Real `WalletFile` + tempfile (§6.4) |
| 3 | Minimal orchestrator churn | Append `F` only; defer full §3 param reorder |
| 4 | Spec fidelity | Amend §2.6 rather than violate wallet-file §4.3 |
| 5 | Adversarial resistance | Reject password cache (memory disclosure); reject MockPersistence contract drift |

### §5.4 R-residuals (Round 1 → Round 2 segments)

| ID | Question | Round 2 segment |
|----|----------|-----------------|
| **R1** | Close vs concurrent refresh | **2a** audit-readiness |
| **R2** | `change_password` should save prefs? | **2b** (confirm today: no) |
| **R3** | Test matrix for lifecycle rewires | **2c** |
| **R4** | Wider-substrate audit (mempool, reorg, …) | **2i** per template §6 |
| **R5** | `spawn_blocking` for disk IO | **2g** close-out default: reject at V3.0 |
| **R6** | V3.1 multisig durable-state shape vs §2.6 three-method surface | **Round 1 pin below**; reopen §2.6 amendment if audit fails |
| **R7** | `Credentials` lifetime in Stage 4 mailbox (owned vs borrowed in messages) | **2d** |
| **R8** | Close / drop vs in-flight `save_state` (Stage 4 observation-only drop; §2.8.5–2.8.6) | **2a** (with R1) |
| **R9** | Periodic flush vs session secret shape (F5) | **Round 1 disposed §5.9** — F5(b) |
| **R10** | `type Error: Into<OpenError>` incoherent for saves (F6) | **Round 1 pin §5.10**; lands in **C0** |
| **R11** | M1 MFA at open/rotate only; trait steady-state invariant (§5.9.1) | **Round 1 pin**; V3.1+ implementation |

#### §5.4.1 R6 — V3.1 multisig forward compatibility (Round 1 pin — reviewer read)

**Question.** Does V3.1 multisig require a different `PersistenceEngine`
shape than `save_state(credentials, ledger)` + `save_prefs` +
`rotate_password`?

**Substrate ([`PQC_MULTISIG.md`](../PQC_MULTISIG.md) read 2026-05-27).**

| Durable concern | Where it lives | PersistenceEngine? |
|-----------------|----------------|---------------------|
| Group setup (§5.5 step 8): own keypairs, N peer pubkeys, `group_id`, version, threshold, DKG secret, acknowledgments, **`tx_counter`** | Wallet-file format extension (spec: new fields / version bump on existing v1 envelope — `m_pqc_multisig_*` class) | Via **`WalletLedger` schema extension** → `save_state(ledger)` |
| Per-output `PersistedMultisigOutput` (§8.4) | Chain-reconstructible; scan → ledger | Same |
| FROST commitments / signing shares | `MultisigSigningSession`; RPC-server-scoped; **not** across restart | **No** — not `PersistenceEngine` |
| File-based signing transport blobs | User-chosen paths outside wallet pair | **No** |
| In-memory `MultisigState` | [`WALLET_RPC_RUST.md`](../WALLET_RPC_RUST.md): separate `Mutex` from wallet lock; flush path still normal wallet file | Orchestrator concern, not trait shape |

**Round 1 disposition (proposed — pending sign-off).**

**§2.6 three-method surface is forward-compatible for V3.1.** Durable
multisig state is **(group setup + acknowledgments + `tx_counter` + output
metadata)** riding a **`WalletLedger` extension** and normal wallet-file
flush — not a separate persistence trait or atomic co-flush of off-ledger
blobs.

**`tx_counter` note.** Replay protection may require **`save_state` outside
`close`** (increment counter, then emit signing material). The **current
trait surface can do that** (call `save_state` more often); what changes is
**orchestrator** pattern and **R9** credential availability at those call
sites — not multisig-specific trait methods.

**Known-future-amendment triggers (reversion clause).** Reopen Phase 0a /
§2.6 if:

1. V3.1 multisig requires **atomic co-flush** of coordinator round state
   with `.wallet` + `.wallet.keys` + prefs **outside** `WalletLedger`
   serialization; or
2. Multisig requires **synchronous `save_state` calls outside the close
   path** with **credential-availability constraints** that V3.0
   close-only orchestration cannot satisfy (e.g. fsync between
   `tx_counter` increment and signing-blob emission when the session
   cannot hold sealing material — overlaps **R9**).

Until a trigger fires, R6 does **not** block Round 1 closure (subject to
R9 / R10).

### §5.5 Round 1 disposition (accepted — F5(b))

**Accepted — §8.2 / Phase 0a trait shape** (§5.9; Appendix A):

- `save_state(&self, state_key: &StateWrapKey<'_>, ledger)`
- `save_prefs(&self, prefs_key: &PrefsHmacKey<'_>, prefs)`
- `rotate_password(&self, old: &Credentials<'_>, new: &Credentials<'_>, new_kdf)`

**Accepted — orchestrator session cache:** `Engine` (then `Wallet`) holds
`Zeroizing<StateWrapKey>` and `Zeroizing<PrefsHmacKey>` from successful
open; password material is **not** resident during steady-state sync.

**Accepted — R10:** `type Error: Into<PersistenceError>` (§5.10).

**Rejected:** F5(a) password on `Engine` for periodic flush; session password
cache in `WalletFile`; `LocalPersistence` deferral; steady-state
`save_state(Credentials, …)`; M2 verification-only MFA (§5.9.1).

**Also pinned:** `F: PersistenceEngine`; `WalletFile` + `Mutex`; async inline
sync IO; `map_persistence_error`; implementor in `shekyl-engine-core` when
orchestrator types are needed.

### §5.8 Why the trait exists (load-bearing purpose)

The trait exists to make the **Stage 4 actor boundary explicit** — direct
`WalletFile` call today vs `ActorRef<PersistenceActor>` mailbox dispatch
tomorrow — **not** to abstract over multiple competing persistence
backends. At Stage 1 there is one implementor (`WalletFile`); at Stage 4
the **second implementor is structural** (the kameo-wrapped actor
implementing the same trait). That single-implementor-through-V4 stance is
**durable** unless a separate storage backend (e.g. redb/LMDB wallet store)
lands with its own design PR and §1.5 justification.

**Auditable trait types** are a first-class property, not a side effect.
`&StateWrapKey<'_>` vs `&Credentials<'_>` on `save_state` makes the
**capability level of each call site** grep-visible: steady-state seal vs
password-handling (`rotate_password` only). That pays off in year-two
audits when reviewers map secret flow without re-deriving the wargame.
Preserve in trait/module rustdoc (C1).

Rejecting `LocalPersistence` is **architectural-integrity-now** (no
deferral wrapper), not "we might plug in alternates later." See §5.6 row
for anti-pattern citation pairing.

**Rewrite collision (F7).** PR 6 lands trait extraction on `Engine<S, …>`
knowing [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) Phase 1 polishes
`Engine` and eventually exposes a public `Wallet` orchestrator — **not**
a rename-in-place. **`PersistenceEngine` and `F: PersistenceEngine` survive
the rewrite**; `Engine::close` / `change_password` call sites are
**consumer-fodder** and will move to `Wallet::close` with the same trait
dispatch. §6.1 describes **PR 6** behavior on `Engine`, not V3.1 final
orchestrator type name.

### §5.9 R9 — Session secrets and trait surface (F5 — Round 1 disposed)

**Threat model (§3.2 principle 7, narrowed).** Primary anchor: **memory
disclosure** during a wallet session (heap, debugger, swap, core dump,
malicious in-process code). Secondary: **disk** wallet file leak. Wargame
compares **blast radius** when memory is read — not probability of leak.

**Periodic flush is load-bearing.** Rewrite-era sync may call `save_state`
every block / on an interval (`flush_every_block` / `on_flush` patterns;
wallet2 autosave). Close-only flush loses hours of scan progress on crash.
If flush is required, **(c) re-derive Argon2 every save** is rejected for
the periodic path (hundreds of ms per block on mobile). A **session cache**
is required; the design choice is **what** is cached.

#### KEK hierarchy (amended v1 — [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §2.6,
[`WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md`](WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md))

| Layer | Spec name | Derivation |
|-------|-----------|------------|
| Password wrap | `wrap_key` | `Argon2id(password, wrap_salt, kdf_params)` → 32 B |
| File master | `file_kek` | Random 32 B; encrypted under `wrap_key`; **transient at open** (HKDF PRK, then zeroize for F5(b)) |
| Region 1 (spend keys) | `wrap_key_region_1` | `HKDF-Expand(file_kek, info = b"shekyl-region1-aead-v1" \|\| addr, L=32)` |
| Region 2 (ledger) | `wrap_key_region_2` | `HKDF-Expand(file_kek, info = b"shekyl-region2-aead-v1" \|\| addr, L=32)` |
| Prefs HMAC | `prefs_hmac_key` | `HKDF-Expand(file_kek, info = b"shekyl-prefs-hmac-v1" \|\| addr)` per [`WALLET_PREFS.md`](../WALLET_PREFS.md) §2.2 |

**One key, one purpose** — region 1 and region 2 no longer share raw `file_kek`
as the AEAD key. AAD prevents ciphertext swapping; HKDF provides **key-purpose
separation** for memory-disclosure (the F5(b) threat model).

**`StateWrapKey` at trait surface** wraps **`wrap_key_region_2`** (steady-state
ledger seal). **`PrefsHmacKey`** remains the prefs integrity sub-key. Open path:
derive `wrap_key_region_1` → decrypt region 1 → read `addr` → derive
`wrap_key_region_2` + `prefs_hmac_key` → **zeroize `file_kek` and
`wrap_key_region_1`** before steady-state sync.

**Implementation alignment (pre-HKDF code).** `WalletFile` caches
`prefs_hmac_key` at open (`handle.rs:215–222`). Reference code may still AEAD
with raw `file_kek` until the HKDF + F5(b) commits land. **PR 6 C2c** targets
session-cached `wrap_key_region_2` per amended §4.3 — not `seal_state_with_file_kek`.

#### Wargame summary

| Option | Steady-state cache | Memory-disclosure blast radius |
|--------|-------------------|--------------------------------|
| **(a) Password on `Engine`** | `Zeroizing` password bytes | **Catastrophic** — password reuse across wallets/accounts; MFA does not fix reuse (§5.9.1) |
| **(b1) `file_kek` on `Engine`** | Full file master key | Decrypt region 1 + 2 if attacker also has `keys_file_bytes` (WalletFile already holds both) — **spend authority** in process |
| **(b3) Typed sealing handles** | `StateWrapKey` + `PrefsHmacKey` | **Region 2 + prefs scope at this rotation** from steady-state cache alone — **not** region 1 (spend keys) if `file_kek` / `wrap_key_region_1` were zeroized after open per HKDF §4.1. Still **decisively smaller** than (a): no password reuse; bounded by `rotate_password`. |

**Disposition: F5(b) with typed handles** — maps to amended v1 crypto as:

- **`StateWrapKey`** — newtype for **`wrap_key_region_2`** (HKDF-derived;
  independent AEAD key from region 1). Trait rustdoc states the mapping
  (Phase 0o / C1). Grep-ability at call sites is unchanged; the type now
  matches a **real** cryptographic boundary, not naming-only intent.
- **`PrefsHmacKey`** — existing crate type; third HKDF expansion from `file_kek`.

**Rejected:** (a); steady-state `Credentials` on trait methods; password
cache in `WalletFile`.

#### Trait surface (Phase 0a)

```rust
async fn save_state(
    &self,
    state_key: &StateWrapKey<'_>,
    ledger: &WalletLedger,
) -> Result<(), Self::Error>;

async fn save_prefs(
    &self,
    prefs_key: &PrefsHmacKey<'_>,
    prefs: &WalletPrefs,
) -> Result<(), Self::Error>;

async fn rotate_password(
    &self,
    old: &Credentials<'_>,
    new: &Credentials<'_>,
    new_kdf: KdfParams,
) -> Result<(), Self::Error>;
```

**Orchestrator:** at `open_full`, Argon2 → unwrap `file_kek` → HKDF region
keys → decrypt region 1 → derive `StateWrapKey` (`wrap_key_region_2`) +
`PrefsHmacKey` → **zeroize password, `file_kek`, `wrap_key_region_1`**.
Periodic refresh / `on_flush` borrows cached sealing keys only.
**`rotate_password`** re-runs password path, re-derives all subkeys, updates
wrap layer per spec §4.2 (`file_kek` unchanged; region ciphertexts unchanged).

**R7 (Stage 4 mailbox):** messages carry **owned or borrowed
`StateWrapKey` / `PrefsHmacKey`**, not `Credentials` — align in segment
**2d** after trait lands.

**Honest scope note (pair with §3.7 and rustdoc).** With per-region HKDF
(amendment doc §3.1), a leaked orchestrator `StateWrapKey` decrypts **region 2
(ledger cache) at this rotation**, not region 1 spend material — **provided**
open path zeroized `file_kek` and `wrap_key_region_1` as prescribed. F5(b)
vs F5(a) unchanged (no password reuse). **Residual:** `WalletFile` may still
retain `keys_file_bytes` (and, until C2c/HKDF land, `file_kek` in the
implementor); scraping the **whole handle** remains worse than orchestrator
cache alone — [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.2 (handle slimming).
**Pre-genesis:** wallets sealed under raw-`file_kek` region AEAD do not
decrypt under amended derivation; KAT regen + `rm -rf ~/.shekyl` per HKDF doc
§2.1 — not PR 6 migration code.

### §5.9.1 R11 — MFA (M1) forward compatibility (V3.1+ pin)

**Roadmap:** YubiKey / FIDO2 **M1 only** — factor contributes to open-path
KEK derivation (`file_kek` unwrap requires password **and** MFA material).
**Reject M2** (decrypt-with-password then UI TOTP gate) — bypassable by any
tool that skips the wallet binary.

**Composition with F5(b):**

| Phase | Password | MFA | Cached on `Engine` |
|-------|----------|-----|-------------------|
| `open_full` | Once | Once (hardware) | Derive → `StateWrapKey` + `PrefsHmacKey`; drop password |
| Steady-state sync | Absent | Absent | Sealing keys only |
| `rotate_password` | Old + new | Re-prove as needed | Refresh sealing keys after rewrap |

**Trait invariant (R11):** `save_state` / `save_prefs` **do not** gain MFA
parameters. MFA complexity lives in **`Engine::open_*`** and
`rotate_password` orchestration only — same trait shape as password-only
V3.0.

**Reversion trigger (R11):** reopen if product requires **fresh MFA proof
per periodic `save_state`** (e.g. touch YubiKey every autosave).

**Seed sovereignty (user-facing, not on trait):** MFA gates the **wallet
file**; **seed** gates **identity recovery**. Document in wallet UX, not
PR 6 trait.

### §5.10 R10 — `type Error` must not be `OpenError` (F6 — Round 1 pin)

Pinned §2.6 has `type Error: Into<OpenError>`. `OpenError` is lifecycle-
open vocabulary (wrong password, network mismatch, outstanding pending).
Save failures (disk full, atomic rename failure, fsync error, oversize
blob) are **lossy and misleading** when squeezed into open-shaped variants.

**Round 1 disposition (proposed).** Phase 0a amends §2.6 to:

```rust
type Error: Into<PersistenceError>;  // new enum in engine/error.rs
```

`map_persistence_error(WalletFileError, …) -> PersistenceError` at the
Engine boundary; `OpenError` remains for `create` / `open_*` / `close`
orchestration only. Wallet-file errors from save map through
`PersistenceError::WalletFile { .. }` or `#[from]` via `IoError` — exact
shape closed in **2g**; direction fixed in Round 1.

### §5.11 Engine vs `Wallet` orchestrator (F7)

[`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) Phase 1: polish
`shekyl-engine-core::Engine`, not a parallel trait re-derivation.
**Public `Wallet` for binaries** is Phase 1+; Stage 1 already landed traits
on `Engine`. PR 6's job is **trait + `F` on `Engine`**; rewrite later
**re-homes** the same `PersistenceEngine` calls on `Wallet::close` /
periodic flush hooks. Energy on §5.2 prior-PR analysis is bounded; energy
on trait + R9/R10 forward-proofing is not.

### §5.6 Anti-pattern check (§8.3.2)

Cite worked-example PR/segment per template §3.3; run at Round 1 / Round 2 /
R-residual altitude.

| Anti-pattern | Worked example | PR 6 disposition |
|--------------|----------------|------------------|
| Cost-benefit-defer-to-later | PR 3 KeyEngine Round 2 workflow pivot; PR 5 segment 2b | Direct `WalletFile` impl + `Mutex` now — no `LocalPersistence` deferral wrapper (**§5.8**: purpose is actor portability, not multi-backend abstraction) |
| User-protection-defaults-in-user-absent-contexts | PR 4 F1 R17 (encrypted persistence opt-in rejected) | Reject password cache in `WalletFile`; **F5(b)** session sealing keys on orchestrator, not password (§5.9) |
| MockPersistence / test double drift | PR 3 §6.4 precedent; spec §6.4 | Real `WalletFile` + tempfile only |
| Landing vs spawn graph conflation | PR 4 pre-flight; §8.1 vs §2.8.3 | §3.5: PR 6 lands on `dev`; Stage 4 spawn is separate |
| Audits-are-clean-so-compress | `16-architectural-inheritance.mdc` | Run full §3.4 + segment **2i** anyway |

### §5.7 Round 1 closure checklist (template §4.2 — closed 2026-05-27)

- [x] Load-bearing question reframed (§5.1) and disposed (§5.5, §5.9).
- [x] Lens 1 applicability recorded (**bounded at trait surface**; §5.0).
- [x] Lens 2 / 3 applicability recorded (N/A at trait surface; F3 in §3.7).
- [x] §3.4 implementor vs trait-surface split written.
- [x] §5.8 trait purpose + auditable types written.
- [x] R6 multisig forward-compat pin (§5.4.1).
- [x] R9 F5(b) wargame; HKDF substrate amendment synced (§5.9).
- [x] R10 `PersistenceError` pin (§5.10).
- [x] R11 MFA M1 forward-compat pin (§5.9.1).
- [x] F7 Engine vs `Wallet` (§5.11).
- [x] Phase 0a′ + HKDF region derivation cross-ref (layout-only; KAT regen out of PR 6 C0).
- [x] R-residuals R1–R8, R11 → Round 2 segment pointers.
- [x] Reopen criterion in status banner.
- [x] Reviewer sign-off — Round 1 closed.
- [x] §7 discipline: Round 2–3 inline on design branch.

---

## Round 2 — segment plan (not started)

Per template §5. **R9 is closed in Round 1** (§5.9) — not segment 2e
decision work. **C2c / Phase 0n** is implementation verification of
cached-`wrap_key_region_2` autosave (post-HKDF). Segments land **inline** on
`feat/stage-1-pr6-persistence-engine-design`.

| Segment | Scope | R-residuals |
|---------|-------|-------------|
| **2a** | Audit-readiness: close vs refresh / pending; **R8** cancellation / §2.8.5–2.8.6 (`close` must await persist completion at Stage 4) | R1, R8 |
| **2b** | `change_password` prefs flush; lifecycle parity | R2 |
| **2c** | Test matrix + call-site sweep pins | R3 |
| **2d** | **R7** mailbox carries `StateWrapKey` / `PrefsHmacKey`; **F3** rustdoc on `rotate_password` invariant | R7 |
| **2g** | Close-out: finalize §4 (incl. R10 `PersistenceError`), §6 matrix, Round 3 readiness gate | R5, R10 |
| **2i** | Wider-substrate audit (template §6 — **required** after 2g) | R4 |

**2g close-out checklist (template §5.3):** all R1–R8, R11 disposed; §4 pins
binding-form-pinned; §6 filled; §5.6.9 discipline matrix complete;
segment 2i landed before Round 3 opens.

### §5.6.9 Discipline-citation matrix (Round 2 segment 2g deliverable)

*Placeholder — fill at 2g close-out per template §7.*

| Discipline | Cited at | Inherited substrate |
|------------|----------|---------------------|
| §8.3.1 lens 1 (bounded) | §3.3, §5.0 | PR 4 bounded lens; PR 5 §5.0 when multi-actor |
| §8.3.2 anti-patterns | §5.6 | This table + segment dispositions |
| §8.3.3 closure rule | Status banner, §5.7 | PR 5 Round 1–3 structure |
| §8.3.4 §7.X / sub-commits | §7.X | Seven-commit shape + deviation rationale |
| Principles 4–8 | §3.2 | WALLET_REWRITE_PLAN |
| Architectural inheritance | §3.4 | Implementor confirmation + trait-surface convergent-constraint row |
| Wider-substrate audit | Segment 2i | TBD |

---

## §6 Review checklist (Round 2 close-out target)

Fill binding-check matrix at Round 2 segment **2g**. Mechanical gates:

- [ ] `cargo fmt --check`
- [ ] `cargo clippy -p shekyl-engine-core -p shekyl-engine-file --all-targets -- -D warnings`
- [ ] `cargo test -p shekyl-engine-core -p shekyl-engine-file`
- [ ] No new workspace deps without [`17-dependency-discipline.mdc`](../.cursor/rules/17-dependency-discipline.mdc)
- [ ] §3.3 benches: **none expected** for persistence hot path
- [ ] §8.2: spec amendment commit (C0) separate from consumer commits
- [ ] Grep: no `MockPersistence`
- [ ] Grep: steady-state `save_state` / `save_prefs` use sealing keys; `rotate_password` uses `Credentials`

### §6.1 Reviewer gate — flush paths, `Engine::close`, advisory lock

**Steady-state periodic flush (rewrite-era; PR 6 wires trait, may not land
caller yet):**

1. `Engine` holds session `StateWrapKey` + `PrefsHmacKey` from `open_full`.
2. Refresh / `on_flush` → `persistence.save_state(&state_key, &ledger).await`
   (and `save_prefs` when prefs change) — **no password**, no Argon2 per call
   after §4.3 / 0n amendment.

**`Engine::close` (PR 6 target):**

1. Refuse if `pending.outstanding() > 0`.
2. `LocalLedger::read()` → `persistence.save_state(&state_key, &ledger).await`.
3. `persistence.save_prefs(&prefs_key, &prefs).await`.
4. Drop `self` → `WalletFile::drop` releases advisory lock on `<base>.wallet.keys`.

**Lock owner:** `WalletFile` inside `F: PersistenceEngine` (default
`WalletFile`). `Engine` holds no separate lock.

**Long-running wallet-RPC process.** For `shekyl-wallet-rpc`, the advisory
lock is held for **process lifetime** (potentially weeks), not one
`Engine::close` — intentional single-writer guarantee. Lock release aligns
with **process shutdown** / final `close_wallet`, not with every RPC idle
period. PR 6 does not change that model.

**Rewrite note.** §6.1 gates **`Engine::close`** at PR 6 land; Phase 1
`Wallet::close` will inherit the same persistence sequence via
`PersistenceEngine` (§5.11).

**`change_password`:** `PersistenceEngine::rotate_password` with
`Credentials`; envelope rewrap only.

---

## §7 Fenceposts — remaining rounds

| Round | Deliverable | Status |
|-------|-------------|--------|
| **Round 2** | Segments 2a–2g + 2i wider-substrate audit; §4/§6 finalized; §5.6.9 discipline matrix | **Not started** |
| **Round 3** | §7.X commit decomposition + readiness gate | **Not started** |
| **Phase 1** | C0–C7 on `feat/stage-1-pr6-persistence-engine` | Blocked on Round 3 |

### §7.1 Stage 1 closeout (do not conflate with PR 6 alone)

Update [`STAGE_1_COMPLETION_AUDIT.md`](STAGE_1_COMPLETION_AUDIT.md) and
spec §1 banner only after **PR 6 + PR 7** land.

---

## §7.X Phase 1 commit decomposition (Round 3 deliverable — provisional)

**Deviation from template §8.2 eight-commit default:** Persistence has no
`SnapshotId`, no diagnostic enum, no `Signer`/`OutputSelector` secondary
traits, no `FaultInjecting` wrapper at V3.0 (bounded lens). **Seven commits
C0–C7** with named rationale recorded here per template §8.2.

| Commit | Scope | Phase 0 pins |
|--------|-------|--------------|
| **C0** | Doc-only: §2.6 three-method shape; `PersistenceError`; `WALLET_FILE_FORMAT` §4.3; this doc | 0a–0c, 0a′, 0j, 0m |
| **C2c** | HKDF region keys in envelope + `seal_state_*` with `wrap_key_region_2`; `WalletFile::save_state(StateWrapKey, …)` | 0n (+ HKDF impl dep) |
| **C1** | `traits/persistence.rs` + re-export; trait rustdoc (0o: `StateWrapKey`, `rotate_password` cache invalidation) | 0e, 0o |
| **C2a** | `shekyl-engine-file`: `WalletFileState` + `Mutex`; `rotate_password` → `&self` | 0d |
| **C2b** | `shekyl-engine-file`: `base_path()`; `save_as` internal paths | 0i |
| **C3** | `impl PersistenceEngine for WalletFile` + `map_persistence_error` | 0h |
| **C4** | `Engine<…, P, F>` + `persistence` field + `assemble` / accessors | 0g |
| **C5** | `lifecycle.rs`: `change_password` / `close` via `F`; keep `LocalLedger` bound | 0f |
| **C6** | Tests (lifecycle + `shekyl-engine-file`); no Mock | 0k |
| **C7** | `CHANGELOG.md`, rustdoc, design doc landed banner | — |

**§6 mapping:** CI gates every commit; full test gate **C6**; close/advisory
question verified in **C5/C6**.

**Synthesis banner:** Not required unless Round 2 segments 2h/2i amend §7.X
bodies post–Round-3-original (template §8.4).

---

## Appendix A — Trait surface after Round 1 (post–Phase 0a amendment)

```rust
pub trait PersistenceEngine {
    type Error: Into<PersistenceError>; // R10 — not OpenError

    fn base_path(&self) -> &Path;
    fn network(&self) -> Network;
    fn capability(&self) -> Capability;

    /// On `Ok`, `.wallet` bytes are durable across power loss
    /// (`atomic_write_file`: tmp → fsync → rename → fsync parent).
    ///
    /// Steady-state region-2 AEAD key (`wrap_key_region_2` per
    /// WALLET_FILE_FORMAT_V1 §2.6 / HKDF region derivation doc). Does not
    /// decrypt region 1 (spend keys) when `file_kek` and
    /// `wrap_key_region_1` were zeroized after open (§5.9).
    async fn save_state(
        &self,
        state_key: &StateWrapKey<'_>,
        ledger: &WalletLedger,
    ) -> Result<(), Self::Error>;

    async fn save_prefs(
        &self,
        prefs_key: &PrefsHmacKey<'_>,
        prefs: &WalletPrefs,
    ) -> Result<(), Self::Error>;

    /// Password-handling moment: runs Argon2 on both passwords and
    /// rewraps the wrap layer. On success, any previously cached
    /// `StateWrapKey` / `PrefsHmacKey` held by the orchestrator are
    /// **stale** — re-derive before the next `save_state` / `save_prefs`.
    /// Saving with a stale key fails authentication (Poly1305 MAC failure).
    async fn rotate_password(
        &self,
        old: &Credentials<'_>,
        new: &Credentials<'_>,
        new_kdf: KdfParams,
    ) -> Result<(), Self::Error>;
}
```

Not on trait: `load_state`, `open`, `create` (Q9.11; §2.8).

---

## Appendix B — `WALLET_REWRITE_PLAN.md` cross-cutting locks

PR 6 must not break:

- **`PendingTx` close refusal** — `outstanding_pending_txs()` before persist.
- **Refresh additive-only** — persistence does not merge scan results.
- **RPC locking discipline** — `change_password` may become `&self` on
  `Engine` once `WalletFile` is interior-mutable.

---

## Appendix C — Open questions / FOLLOWUPS (reversion clauses)

| Item | Disposition | Reopen when |
|------|-------------|-------------|
| Full `Engine<S, K, L, E, D, F, R, P>` reorder | Defer | `K` + `E` on `Engine` |
| `LedgerEngine` persist accessor | Defer | `close` needs non-`LocalLedger` |
| `spawn_blocking` for saves | Reject V3.0 | Measured close latency breach |
| `Engine::network()` via `F` | Optional | — |
| V3.1 multisig co-flush outside ledger | §5.4.1 trigger (1) | Multisig design names non-ledger durable blob requiring atomic persist with wallet pair |
| Multisig mid-session `save_state` + credential constraints | §5.4.1 trigger (2) | `tx_counter` / signing path needs flush orchestration V3.0 cannot support |
| Periodic flush credential model | §5.9 R9 | **Closed Round 1** — F5(b) sealing keys on orchestrator |
| MFA per-save on trait | §5.9.1 R11 | Product requires touch-per-autosave |
| `WalletFile` handle slimming | FOLLOWUPS V3.2 | Narrow held state to `PersistenceEngine` needs only |
| Separate redb/LMDB backend | §5.8 | New §1.5 trait or implementor PR |

---

*Template:* [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md).
*Spec:* [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.6, §2.8, §3, §6.4, §8.1–§8.3.
*Process:* [`26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc).
