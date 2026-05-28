# Stage 1 PR 6 — `PersistenceEngine` extraction — design

**Status.** **Design closed — Round 3 complete (2026-05-27); lessons canvass
supplement landed same day (§5.12).** Ready for Phase 1 on
`feat/stage-1-pr6-persistence-engine` after HKDF implementation PR merges to
`dev`. Planning doc branch:
`feat/stage-1-pr6-persistence-engine-design` → PR to `dev`. Opened from `dev`
tip `b9c03dc24` (post–PR #81 `PendingTxEngine` merge). This document follows
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
**Phase 1 implementation** lands on `feat/stage-1-pr6-persistence-engine`
after §6.3 prerequisites (HKDF PR merged to `dev`).

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
not shared-`file_kek` "full wallet." **HKDF envelope implementation + KAT
regen are a prerequisite PR** merged to `dev` before the PR 6 implementation
branch cuts; PR 6 spec-amends (C0) and consumes the landed derivation (C2c).

**Reopen criterion:** quiescence/close-ordering the trait cannot express;
multisig §5.4.1 trigger fires; **or** steady-state trait methods regain
`Credentials`/password parameters (blast-radius regression); **or** a
periodic-flush path requires fresh MFA proof per save (R11 trigger).

**Stage 1 is not complete after this PR.** PR 7 (`EconomicsEngine`)
remains. §1 status banner in
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) and
[`FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 closeout inventory update only after
**both** PR 6 and PR 7 land. A dedicated
`STAGE_1_COMPLETION_AUDIT.md` is **not yet in the tree** — do not link to it
until that doc PR lands.

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

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc):

| Priority | How this PR touches it |
|----------|-------------------------|
| **1 — Security** | Open/rotate: Argon2 + `file_kek` unwrap; steady-state: HKDF-derived `wrap_key_region_2` + `prefs_hmac_key` only (§5.9). `Credentials` on `rotate_password` and open path only. Aligns with [`35-secure-memory.mdc`](../../.cursor/rules/35-secure-memory.mdc) and [`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc). |
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
| `KeyEngine` on `Engine<S, …>` | Follow-up; `Arc<AllKeysBlob>` remains per `V3_ENGINE_TRAIT_BOUNDARIES.md` / FOLLOWUPS V3.0 inventory |
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
- [x] **Surface amend vs preserve.** **Amends** §2.6: steady-state
  `save_state` / `save_prefs` take **`StateWrapKey` / `PrefsHmacKey`**
  (F5(b), §5.9); `rotate_password` keeps `Credentials`. Open/rotate password
  paths stay off-trait (Q9.11). Round 1 **rejected** steady-state
  `Credentials` on `save_state`.

### §3.2 Plan-altitude principles (template §3.2 — `WALLET_REWRITE_PLAN.md`)

| Principle | Applicability |
|-----------|----------------|
| **4 — architectural-integrity-now** | **Always applies.** Governs: direct `WalletFile` impl (no `LocalPersistence` deferral); `Mutex` now for `&self` trait; §8.2 / F5(b) amendment now for sealing keys on steady-state saves (not password-on-every-save). Rules: [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc), [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc). |
| **5 — closure-rule + audit trail** | **Always applies.** Round 1–3 **closed**; lessons canvass §5.12 landed; §7.X commit plan pinned; reopen criterion in status banner. |
| **6 — wider-substrate audit** | **Applies.** Closed in Round 2 segment **2i** (§5.6.9, G1–G6). |
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

- [x] [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule 2: design
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
| `save_state` | `(&self, state_key, ledger)` (Phase 0a / §5.9) | `(&self, password, ledger)` :480–484 | **F5(b): `StateWrapKey` on trait** (C2c/C3/C7) |
| `rotate_password` | `&self` + `Credentials` | `&mut self` :507–512 | **`Mutex` interior mutability** |
| `base_path` | `&Path` | missing | Delegate to `state_path()` (`paths.rs`) |

**`network` / `capability`:** cached on `Engine` at `assemble` from
`file.network()` / `file.capability()` — **keep cache**; single source at
open.

| R0-D | Finding | Disposition |
|------|---------|-------------|
| R0-D1 | `save_state` password on every call | F5(b): `StateWrapKey` on trait (Phase 0a / §5.9) |
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
| Atomic state writes + durability contract | `atomic_write_file`: tmp → fsync(file) → rename → fsync(parent) (`shekyl-engine-file/src/atomic.rs`). Trait rustdoc: **`Ok(())` = durable across power loss** (Phase 0b / C1). **Not** the region-2 AEAD nonce source — nonces are `OsRng` in `seal_state_file` (§5.12 L7). |
| Region-2 AEAD nonce provenance | Each `save_state` draws a fresh 24-byte `region2_nonce` via `fresh_random_bytes()` → `OsRng` (`wallet_envelope.rs`). Trait rustdoc pins **never counter-derived** (§5.12 L7, Phase **0r** / C1). |
| Ledger snapshot consistency | `save_state` receives a **point-in-time** `WalletLedger` snapshot (Stage 1: `LocalLedger::read()` under guard before call). Snapshot is **immutable** from capture until the implementor finishes serialization (Monero save-during-refresh lesson; §5.12 L5, Stage 4 **2d D4**). |
| mlock / swap exposure (F5(b) contingent) | `StateWrapKey` / `PrefsHmacKey` **SHOULD** live in `mlock`ed pages where the OS permits (`RLIMIT_MEMLOCK` on Linux — default 64 KiB is tight for RPC + Argon2). **Failure to mlock:** log **warning** at `Engine` open; cold-boot/swap exposure possible — not silent success (§5.12 L8, Phase **0s** / C1 rustdoc + deployment guide cross-ref). |
| Panic / crash telemetry redaction | Redacted `Debug` on sealing types does **not** extend to Rust's default panic hook (Slope 2022 lesson). §6.2 panic-hook gate in **C6**; custom hook + subscriber redaction is wallet-RPC / tracing work beyond the trait (§5.12 L1). |
| Release binary integrity | F5(b) blast-radius discipline is moot if the distributed binary is compromised (Atomic Wallet 2023). Upstream defense: signed release tags per [`docs/SIGNING.md`](../SIGNING.md) — cite in §3.7 / C1 module rustdoc (§5.12 L4). |
| Save failure typing | **R10:** `type Error: Into<PersistenceError>` (not `OpenError`; §5.10) |
| Close refuses in-flight pending | Unchanged — `outstanding_pending_txs()` before persist |
| No `load_state` on trait | Q9.11 — construction-only |
| Cross-record consistency under `rotate_password` | Region-2 AAD binds `seed_block_tag` (region-1 Poly1305 tag), not wrap header — **2d D2**. `keys_file_bytes` cache updated on rewrap; region-1 ciphertext unchanged. |

---

## §4 Phase 0 binding-form candidates

Pre-enumeration for Round 2 close-out finalization. **Amendment commits
doc-only** per §8.2.

| Pin | Binding form | Lands in commit |
|-----|--------------|-----------------|
| **0a** | §2.6 three-method shape: `StateWrapKey` / `PrefsHmacKey` / `Credentials` on rotate only + §4 async rows | **C0** |
| **0a′** | Parent spec §4.3 + HKDF region derivation doc cross-ref in §2.6 / Round 6 note: cache **`wrap_key_region_2`** only; `file_kek` transient at open. **Layout unchanged; no `file_version` bump.** Tier-3 KAT regen when `wallet_envelope` implements HKDF — **not in PR 6 C0.** | **C0** (with 0a) |
| **0o** | `StateWrapKey` / `PrefsHmacKey` types: `ZeroizeOnDrop`; redacted `Debug`/`Display`; **no** `Serialize`/`Deserialize`; trait rustdoc (HKDF mapping, rotate invalidates cache, G4 backup warning) | **C1** |
| **0p** | Open-path ritual: derive subkeys → zeroize `file_kek` + `wrap_key_region_1` before returning `Engine`; test gate | **C5** + **C6** |
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
| **0l** | Stage 4: `ActorRef<PersistenceActor>` same trait; **D3–D6** mailbox/supervisor/runtime pins | doc only |
| **0r** | Region-2 nonce: `OsRng` per save; never counter-derived (trait rustdoc) | C1 |
| **0s** | mlock attempt + warn-on-failure for sealing keys (§3.7 honest F5(b)) | C1 rustdoc + open path when types land |
| **0t** | Bounded mailbox + save coalescing (Stage 4 implementor; cross-ref **2d D3**) | C0/C1 rustdoc |
| **0m** | R6: §2.6 forward-compatible with V3.1 multisig per §5.4.1; amendment triggers named | **C0** (doc confirm) |
| **0n** | Additive `save_state_with_key(&StateWrapKey, &WalletLedger)`; consumes HKDF region keys from **prerequisite PR**; old `save_state(password, …)` stays until **C7** | **C2c** |

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
| **R1** | Close vs concurrent refresh | **2a** — **closed** (structural `close(self)`; Stage 4 await pin) |
| **R2** | `change_password` should save prefs? | **2b** — **closed** (orchestrator `save_prefs` after rotate) |
| **R3** | Test matrix for lifecycle rewires | **2c** — **closed** |
| **R4** | Wider-substrate audit | **2i** — **closed** (G1–G6) |
| **R5** | `spawn_blocking` for disk IO | **2g** — **closed** (reject V3.0) |
| **R6** | V3.1 multisig durable-state shape vs §2.6 three-method surface | **Round 1 pin §5.4.1** |
| **R7** | Sealing-key / `Credentials` lifetime in Stage 4 mailbox | **2d** — **closed** (owned in messages) |
| **R8** | Close / drop vs in-flight `save_state` | **2a** — **closed** (§2.8.6 await pin) |
| **R9** | Periodic flush vs session secret shape (F5) | **Round 1 disposed §5.9** — F5(b) |
| **R10** | `type Error: Into<OpenError>` incoherent for saves (F6) | **Round 1 pin §5.10**; lands in **C0** |
| **R11** | M1 MFA at open/rotate only; trait steady-state invariant (§5.9.1) | **Round 1 pin**; V3.1+ implementation |

#### §5.4.1 R6 — V3.1 multisig forward compatibility (Round 1 pin — reviewer read)

**Question.** Does V3.1 multisig require a different `PersistenceEngine`
shape than `save_state(&StateWrapKey, ledger)` + `save_prefs(&PrefsHmacKey, …)` +
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

### §5.10 R10 — `type Error` must not be `OpenError` (F6 — Round 1; **Round 3 amendment**)

Pinned §2.6 has `type Error: Into<OpenError>`. `OpenError` is lifecycle-
open vocabulary (wrong password, network mismatch, outstanding pending).
Save failures (disk full, atomic rename failure, fsync error, oversize
blob) are **lossy and misleading** when squeezed into open-shaped variants.

**Trait error (Phase 0a / C0):**

```rust
type Error: Into<PersistenceError>;  // engine/error.rs
```

```rust
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("wallet file error: {0}")]
    WalletFile(#[from] shekyl_engine_file::WalletFileError),
    #[error("prefs error: {0}")]
    Prefs(#[from] shekyl_engine_prefs::PrefsError),
}
```

**Orchestrator mapping (Round 3 pin — do not collapse back into `Io`).**

| Path | Error type | Rationale |
|------|------------|-----------|
| `PersistenceEngine::{save_state, save_prefs, rotate_password}` | `PersistenceError` | R10 — save/rotate vocabulary |
| `Engine::close` | `OpenError::Persistence(#[from] PersistenceError)` | **New variant** — preserves type-level separation at the lifecycle boundary |
| `Engine::change_password` | `ChangePasswordError` (below) | Partial-failure semantics (**2b** amendment) |

```rust
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    // … existing variants …
    #[error("persistence failure during close: {0}")]
    Persistence(#[from] PersistenceError),
}

#[derive(Debug, thiserror::Error)]
pub enum ChangePasswordError {
    #[error("password rotation failed: {0}")]
    RotateFailed(#[from] PersistenceError),
    #[error("password rotated but prefs flush failed: {0}")]
    RotatedButPrefsFlushFailed(#[from] PersistenceError),
}
```

Mapping `PersistenceError` → `OpenError::Io(IoError::WalletFile { … })` is
**rejected** — it undoes R10. C3/C5 wire the shapes above mechanically.

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

## Round 2 — segment plan (closed 2026-05-27)

Per template §5. **R9 is closed in Round 1** (§5.9) — not segment 2e
decision work. **C2c / Phase 0n** is implementation verification of
cached-`wrap_key_region_2` autosave (post-HKDF). Segments land **inline** on
`feat/stage-1-pr6-persistence-engine-design` (one commit per segment batch
unless the user requests finer splits).

| Segment | Scope | R-residuals | Status |
|---------|-------|-------------|--------|
| **2a** | Audit-readiness: close vs refresh / pending; **R8** §2.8.6 | R1, R8 | **Closed** |
| **2b** | `change_password` prefs flush; lifecycle parity | R2 | **Closed** |
| **2c** | Test matrix + call-site sweep pins | R3 | **Closed** |
| **2d** | **R7** mailbox; **F3** rustdoc; **D3–D6** bounded mailbox / supervisor / runtime | R7 | **Closed** (amended §5.12) |
| **2g** | Close-out: §4 / §6 / Round 3 gate; **R5**, **R10** | R5, R10 | **Closed** |
| **2h** | Open-path HKDF ritual + `file_kek` non-retention gate | — | **Closed** (Round 3) |
| **2i** | Wider-substrate audit (template §6 — after 2g) | R4 | **Closed** |

### Round 2 segment 2a (2026-05-27) — audit-readiness (R1, R8)

*Round 3 amendments: **A1**, **A2** below.*

**R1 — close vs concurrent refresh.**

**Steelman.** A long-running `refresh` holds `&mut Engine` (or, at Stage 4,
drives concurrent ledger mutation via `RefreshEngine` messages) while another
task calls `close` and persists a stale ledger snapshot — classic TOCTOU on
wallet state.

**Stage 1 structural defense (today).** [`Engine::close`](../../rust/shekyl-engine-core/src/engine/lifecycle.rs)
takes `self` by value. Direct calls on one `Engine` value cannot race `&mut self`
refresh with `close(self)`.

**A1 (Round 3) — `Arc` / background refresh.** Production refresh uses
`Arc<RwLock<Engine<…>>>` (background task holds a clone). `close` requires:
(1) stop/join the refresh task so no live `Arc` holders remain;
(2) `Arc::try_unwrap` (or equivalent) to recover unique `Engine` ownership;
(3) then `close`. Failure at step 2 is a **runtime** error, not a borrow-checker
error. §6.1 gates orchestrator discipline: **refresh quiesced before close**.

`close` sequence (unique ownership assumed):

1. `outstanding_pending_txs() == 0` (PR 5 lock).
2. `ledger.read()` → `save_state` → `save_prefs`.
3. `drop(self)` → advisory lock release.

No concurrent writer on `LocalLedger` exists after the pending check because
`close` consumes the orchestrator.

**Stage 4 pin (observation-only for PR 6; load-bearing at actor cutover).**
Per [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.8.5–2.8.6:

- Teardown stops `RefreshEngine` / `PendingTxEngine` **before** ledger final
  flush; `PersistenceEngine` runs **last** in group A′.
- `Engine::close` **must await** `PersistenceActor` completion of the final
  `save_state` / `save_prefs` messages before returning `Ok` — not merely
  enqueue them. §2.8.6: `drop` without `close` may let a persistence actor
  commit after the caller believes the wallet is gone.

**Disposition.** R1 **closed.** PR 6 documents the Stage 1 structural property
in §6.1; adds Phase **0l** rustdoc cross-ref to §2.8.6 on the trait module.
No trait method for "quiesce refresh" — quiescence is orchestrator teardown
order, not `PersistenceEngine` surface.

**R8 — in-flight `save_state` vs `close` / drop.**

**Stage 1.** `save_state` is synchronous inside the async trait method body;
`close` runs saves to completion before `drop(self)`. No background persist
task.

**Stage 4.** Same await rule as R1: `close` awaits persistence replies.
Trait methods remain `async` so the await point exists at the orchestrator.

**A2 (Round 3) — cancellation safety on `close`.** Pin in `Engine::close`
rustdoc (C5) and §6.1:

| When `close` future is dropped | Persist outcome | Caller obligation |
|-------------------------------|-----------------|-------------------|
| Before `save_state` await starts | Not saved | Safe to treat as not closed |
| During `save_state` / `save_prefs` await | **Unknown** | Must reopen and verify ledger/prefs; do not assume durability |
| After successful await | Saved | Normal close |

**Disposition.** R8 **closed** with §2.8.6 await pin + **A2** cancellation table.

---

### Round 2 segment 2b (2026-05-27) — R2 `change_password` prefs flush

*Round 3 amendment: **B1**.*

**Question.** Should `change_password` also persist `.prefs.toml`?

**Today (`lifecycle.rs` + `handle.rs`).** `Engine::change_password` calls
`WalletFile::rotate_password` only. Rotation rewraps the `file_kek` wrap layer
in `.wallet.keys`; **region 1 ciphertext and `.wallet` bytes are unchanged**
(`rotate_password_preserves_region1_and_state` test). `prefs_hmac_key` is
HKDF-derived from unchanged `file_kek` — **no prefs key rotation** on password
change.

**Gap.** In-memory `WalletPrefs` may have diverged from disk (subaddress
labels, settings) while the user rotates password. Crash before `close` loses
prefs edits even though the new password unlocks the wallet.

**Disposition.** R2 **closed — orchestrator flush, no trait change.**

- **`PersistenceEngine` stays three methods.** Password rotation is
  `rotate_password`; prefs durability is `save_prefs`.
- **`Engine::change_password` (C5)** returns `Result<(), ChangePasswordError>`
  (§5.10) and calls, in order:
  1. `persistence.rotate_password(old, new, new_kdf).await` →
     `ChangePasswordError::RotateFailed` on failure.
  2. On success: orchestrator sealing keys remain valid today (`file_kek`
     unchanged); document explicitly. If a future rotation replaces `file_kek`,
     orchestrator **must** re-derive `StateWrapKey` + `PrefsHmacKey`.
  3. `persistence.save_prefs(&prefs_key, &self.prefs).await` →
     **`ChangePasswordError::RotatedButPrefsFlushFailed`** on failure (password
     **did** rotate on disk; caller may retry `save_prefs` only).

**B1 (Round 3).** Reject silent prefs failure after successful rotate. The
caller must know which side of the line they're on.

**Rejected:** new `rotate_password_and_prefs` trait method; skipping prefs flush.

---

### Round 2 segment 2c (2026-05-27) — R3 test matrix + call-site sweep

*Round 3 amendments: **C1** (stale-key tests), **C2** (`save_as`).*

**Call-site sweep (V3.0 production).**

| Site | File | Disposition |
|------|------|-------------|
| `Engine::close` | `lifecycle.rs` | Rewire to `F: PersistenceEngine` + sealing keys (**C5**) |
| `Engine::change_password` | `lifecycle.rs` | Rewire to `rotate_password` + `save_prefs` (**C5**, **2b**) |
| `WalletFile::save_state` | `handle.rs` | Trait impl; `StateWrapKey` param (**C2c**, **C3**) |
| `WalletFile::save_prefs` | `handle.rs` | Trait impl; `PrefsHmacKey` param (**C3**) |
| `WalletFile::rotate_password` | `handle.rs` | Trait impl (**C3**) |
| `WalletFile::save_as` | `handle.rs` | **Out of trait** — inherent clone-to-new-path; runs full open password → Argon2 → seal for a **new** wallet pair with caller-supplied password (**C2**). Not session `StateWrapKey` |
| FFI / GUI | downstream | Unchanged in PR 6; still supply password per save until rewrite |

**Grep gates (§6):** no `MockPersistence`; steady-state paths use sealing keys.

**Test matrix (C6).**

| Test | Crate | Property |
|------|-------|----------|
| `rotate_password_preserves_region1_and_state` | `shekyl-engine-file` | Keep — wrap-only rotation |
| `change_password_rewraps_envelope_then_reopen_uses_new_password` | `shekyl-engine-core` | Keep — extend with prefs round-trip after **2b** flush |
| `close` refuses outstanding pending | `lifecycle.rs` | Keep |
| `create` → `close` round-trip | `lifecycle.rs` | Keep — ledger bytes durable |
| **`persistence_trait_save_state_round_trip`** | `shekyl-engine-core` | **New** — `WalletFile` via `PersistenceEngine`, tempfile, sealing keys from open |
| **`change_password_flushes_prefs`** | `shekyl-engine-core` | **New** — mutate prefs in memory, rotate, reopen, read prefs file |
| **`stale_state_wrap_key_fails_after_rotate`** | `shekyl-engine-core` | **C1** — open → `save_state(k)` ok → `rotate_password` ok → `save_state(k_stale)` → `PersistenceError::WalletFile` with `WalletEnvelopeError::InvalidPasswordOrCorrupt` (region-2 AEAD MAC failure) |
| **`rederived_state_wrap_key_succeeds_after_rotate`** | `shekyl-engine-core` | **C1** — same, but re-derive `StateWrapKey` from open ritual → `save_state` ok |
| **`open_does_not_retain_file_kek`** | `shekyl-engine-core` | **0p / C6** — after `open_full`, orchestrator/`WalletFile` holds `wrap_key_region_2` + `prefs_hmac_key`, not `file_kek` |
| **`panic_hook_does_not_leak_state_wrap_key`** | `shekyl-engine-core` | **§5.12 L1 / C6** — forced panic with `StateWrapKey` in scope; no raw key bytes in panic message |
| HKDF region KATs | `docs/test_vectors/…` | **Prerequisite PR** — not PR 6 C6 |

**Disposition.** R3 **closed**; **C1** tests are load-bearing for F5(b) fail-loud
discipline (Round 3 **F-R3.8**).

---

### Round 2 segment 2d (2026-05-27) — R7 mailbox + F3 implementor rustdoc

*Round 3 amendments: **D1**, **D2**; open ritual in **2h**.*

**R7 — `Credentials` / sealing-key lifetimes in Stage 4 messages.**

| Message | Payload shape | Rationale |
|---------|---------------|-----------|
| `SaveState` | `StateWrapKey` (owned `Zeroizing<[u8; 32]>` or thin newtype) + `WalletLedger` snapshot | Key must outlive `.await`; ledger cloned or snapshotted per existing Stage 4 ledger patterns |
| `SavePrefs` | `PrefsHmacKey` + `WalletPrefs` | Same |
| `RotatePassword` | `Credentials` ×2 owned (`Zeroizing<Vec<u8>>` or fixed-max buffer policy) + `KdfParams` | Password bytes cannot be borrowed across mailbox round-trip |

**Disposition.** R7 **closed — owned material in messages.** Engine holds
session `Zeroizing<StateWrapKey>` / `Zeroizing<PrefsHmacKey>`; each flush
**clones** 32-byte keys into the message (negligible vs disk IO). Reject
`&Credentials` in mailbox (non-`'static` borrow).

**D1 (Round 3) — mailbox queueing for secrets.**

- **`RotatePassword`:** use **`ActorRef::call`** (request/reply), not queued
  `send`, so password material is not parked in a deep mailbox queue under
  backpressure.
- **`SaveState` / `SavePrefs`:** bounded mailbox + back-pressure (lessons
  canvass **§5.12 L3**; amends prior "unrestricted `send`" reading).

**D3 (lessons canvass, 2026-05-27) — bounded mailbox, coalescing, OOM.**

| Property | Pin |
|----------|-----|
| Mailbox depth | **Bounded** default for `PersistenceActor` (`try_send` → `Full`). Unbounded mailbox is a **justified exception** only with documented worst-case memory bound — not the Stage 4 default. |
| Back-pressure | Orchestrator on `Full`: coalesce or skip intermediate saves; never unbounded-queue full `WalletLedger` snapshots. |
| Save coalescing | When multiple `SaveState` are queued, actor **MAY** drop superseded snapshots and process only the latest (**last-write-wins** per §4 idempotency). Final flush before `close` **must** process. |
| OOM class | Unbounded `SaveState` under per-block autosave is a **real** Stage 4 attack surface (each message clones ledger). |

Document in Phase **0l** + **0t** (C0/C1 rustdoc; Stage 4 implementor spec).

**D4 (lessons canvass) — ledger snapshot immutability.**

`SaveState` carries an **owned snapshot** of `WalletLedger` taken at send time;
the actor must not read a live `Arc`/`RwLock` guard across `.await`. Rustdoc:
*"snapshot immutable from capture until serialization completes."*

**D5 (lessons canvass) — `PersistenceActor` crash / supervisor.**

Per `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.8.5: persistence actor failure is
**non-recoverable** at the trait level. Concrete pin for Stage 4:

- Supervisor strategy: **`stop`** (do not restart the actor and continue).
- Orchestrator observes actor stop during `Engine::close` final flush →
  `PersistenceError::ActorCrashed` (or equivalent) surfaced to caller.
- **Not** "restart actor and resume" — wallet may be torn mid-write.

**D6 (lessons canvass) — tokio runtime shutdown without `close`.**

§2.8.6 row: if the tokio runtime is dropped while `Engine` still holds
`ActorRef<PersistenceActor>`, in-flight saves are lost. **wallet-RPC** SIGTERM
handler **MUST** call `Engine::close` (or equivalent drain) before runtime drop.

Document in Phase **0l** (C0 cross-ref to §2.8.6).

**F3 — `rotate_password` cross-record invariant (implementor rustdoc).**

Pin on `WalletFile` / `PersistenceEngine` impl (C3):

- Rewrap updates `keys_file_bytes` cache (wrap layer changes; region-1
  ciphertext bytes unchanged).
- Region-2 AEAD AAD is `magic \|\| version \|\| seed_block_tag` per
  [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §2.2 — **`seed_block_tag`
  is the region-1 Poly1305 tag** (immutable across password rotation because
  region-1 ciphertext is unchanged). AAD does **not** bind to the wrap header.
- Does **not** rewrite `.wallet` region-2 ciphertext on rotate (spec §4.2).
- Orchestrator sealing keys remain valid when `file_kek` unchanged (**2b**).

**D2 (Round 3).** F3 rustdoc must state the `seed_block_tag` AAD binding
explicitly — avoids the self-contradictory "whole keys_file_bytes as AAD"
reading.

**Disposition.** F3 **closed** as implementor rustdoc in C1/C3.

---

### Round 2 segment 2g (2026-05-27) — close-out (R5, R10, §4, §6, Round 3 gate)

**R5 — `spawn_blocking` for disk IO.**

**Disposition.** **Reject at V3.0** — same inline-sync-body pattern as PR 4
`RefreshEngine`. Persistence methods are `async` with synchronous
`atomic_write_file` inside; `Engine::close` remains caller-blocking.

**Reopen when:** measured mobile close-path latency exceeds the rewrite plan's
budget **and** profiling attributes it to persist IO on the async runtime
thread — then evaluate `spawn_blocking` in a dedicated perf PR, not PR 6.

**R10 — `PersistenceError` + lifecycle mapping (finalized Round 3).** See
§5.10. `Engine::close` uses **`OpenError::Persistence(PersistenceError)`** —
not `OpenError::Io`. C3/C5 are mechanical.

**§4 Phase 0.** All pins in §4 table are **binding-form-pinned**; no new pins
surfaced in Round 2.

**§6 binding-check matrix (filled).**

| Check | Source | PR 6 |
|-------|--------|------|
| §2.6 three-method shape + sealing keys | §5.9, Appendix A | C0, C1 |
| `PersistenceError` not `OpenError` on trait | §5.10 | C0, C3 |
| No `load_state` on trait | Q9.11 | C0 |
| `Mutex<WalletFileState>` | §2.6 Round 3 note | C2a |
| Real `WalletFile` tests only | §6.4 | C6 |
| §6.1 flush / close ordering | §6.1, **2a** | C5, C6 |
| `change_password` prefs flush | **2b** | C5 |
| HKDF region keys in envelope | HKDF doc | **Prerequisite PR** merged before implementation branch |
| F5(b) grep gates | §6.2 | C6 / CI |
| Atomic-write tests cited | §6.3 | `shekyl-engine-file/src/atomic.rs` tests |
| G4 backup rustdoc | **2i** | **C1** (blocking) |
| §5.12 lessons canvass blocking items | §5.12 | C1/C6 + **2d** Stage 4 pins |
| Panic-hook redaction test | §5.12 L1 | **C6** |
| KDF-in-AAD / HKDF address | §5.12 L6, L9 | Verified — no substrate amend |

**Round 3 readiness gate (template §8.3) — closed.**

**Lessons canvass supplement (2026-05-27):** §5.12 landed; design remains closed;
Phase 1 inherits new §6.2 panic gate and §3.7 / **2d** pins.

- [x] Round 1 closed (§5.7).
- [x] Round 2 segments 2a–2d, **2h**, 2g, 2i closed (+ Round 3 precision amendments).
- [x] §4 Phase 0 pins enumerated with commit mapping (§7.X).
- [x] §6 mechanical + F5(b) grep gates + prerequisites (§6.2–§6.3).
- [x] §7.X: ten commits, build-at-every-commit order, additive C2c (F-R3.2).
- [x] R10 / `ChangePasswordError` shapes decided (§5.10).

### §5.6.9 Discipline-citation matrix (Round 2 segment 2g)

| Discipline | Cited at | Inherited substrate |
|------------|----------|---------------------|
| §8.3.1 lens 1 (bounded) | §3.3, §5.0, **2a** | Trait surface only; teardown in §2.8.6 |
| §8.3.2 anti-patterns | §5.6, **2b** (no bundle rotate+prefs on trait) | PR 5 MockPersistence precedent |
| §8.3.3 closure rule | Status banner, §5.7, segment headers dated | PR 5 structure |
| §8.3.4 §7.X / sub-commits | §7.X, **2c** test→commit map | Ten commits C0/C1/C2a–c/C3–C7; HKDF prerequisite PR |
| Principles 4–8 | §3.2 | WALLET_REWRITE_PLAN 4–8 |
| Architectural inheritance | §3.4, HKDF amendment | Implementor Shekyl-native; trait earned |
| Wider-substrate audit | **2i** | G1–G6 below |
| §8.3.6 discipline extension | — | No new segment types |

---

### Round 2 segment 2i (2026-05-27) — wider-substrate audit (R4)

Per template §6. Wallet-file / encrypted-state domain (not mempool/reorg —
those live on `RefreshEngine` / `PendingTxEngine`; PR 6 cites them only where
persist ordering depends on them).

**G1 — Second process / stolen lock.**

Monero/Bitcoin lesson: two processes opening the same wallet corrupt state.
Shekyl: advisory lock on `<base>.wallet.keys` (`KeysFileLock`). Second open
fails; RPC holds lock for process lifetime (§6.1).

**PR 6 disposition:** Document in `PersistenceEngine` / `WalletFile` module
rustdoc (C1/C3). No trait change.

**G2 — Power loss during atomic write.**

Lesson: torn writes without tmp→rename→fsync discipline.

Shekyl: `atomic_write_file` + trait rustdoc `Ok(())` = durable (Phase **0b**).

**PR 6 disposition (Round 3 **I1** — resolved).** Existing tests in
[`shekyl-engine-file/src/atomic.rs`](../../rust/shekyl-engine-file/src/atomic.rs):
`writes_to_fresh_target`, `overwrites_existing_target_atomically`,
`multiple_writes_to_same_target_each_land_fully` — prove tmp→rename semantics
and no torn hybrid files under normal OS behavior. **No** simulated power-loss
crash injection in-tree today. PR 6 does not add crash injection; durability
contract is enforced by `atomic_write_file` discipline + trait rustdoc. True
power-loss fault injection is a **V3.2 FOLLOWUPS** candidate if auditors require
it beyond unit-level atomic tests.

**G3 — Disk full / quota / read-only filesystem.**

Lesson: silent truncation or partial writes.

Shekyl: `WalletFileError` / `PersistenceError::WalletFile` surfaces `io::Error`
from tmp write or rename.

**PR 6 disposition:** Map errors in C3; §6 grep confirms no swallowing into
`IncorrectPassword`.

**G4 — Copying `.wallet` while daemon holds lock (backup tools).**

Lesson: `wallet.dat` copy mid-write produces unreadable backup.

Shekyl: docs should say: copy only when wallet closed or use `save_as` to a
quiescent path. **Not** a trait method.

**PR 6 disposition (Round 3 **I2** — blocking).** One sentence in
`PersistenceEngine` / `WalletFile` module rustdoc (**C1**): do not copy the
wallet directory while the advisory lock is held; use `close` + filesystem
copy or `save_as` to a quiescent path. Optional `WALLET_FILE_FORMAT_V1.md`
user-ops cross-ref in **C7**.

**G5 — Network filesystem / NFS close-to-open.**

Lesson: lock semantics break across NFS clients.

**Disposition.** **FOLLOWUPS V3.2** — document "local filesystem only" in
user-facing wallet docs if not already; no code change in PR 6.

**G6 — Password rotation without prefs flush (data loss).**

Lesson: users expect "change password" to persist all wallet state they edited.

**Disposition.** Closed by **2b** orchestrator `save_prefs` after rotate.

**R4 disposition.** **Closed.** G5 is the only new FOLLOWUPS item from 2i;
G1–G4 and G6 land in PR 6 docs/tests as above.

---

### Round 2 segment 2h (2026-05-27) — open-path ritual (Round 3 **H1**)

**Problem.** F5(b) blast-radius is true only if `file_kek` and `wrap_key_region_1`
do not survive past open. The sequence must be explicit and test-gated.

**Open ritual (normative for `Engine::open_full` / `open_*` after PR 6):**

1. Argon2(password) → unwrap `file_kek`.
2. HKDF → `wrap_key_region_1`, `wrap_key_region_2`, `prefs_hmac_key`.
3. Decrypt region 1 with `wrap_key_region_1`; read `expected_classical_address`.
4. Decrypt region 2 with `wrap_key_region_2` (or defer if lost-`.wallet` path).
5. **Zeroize `file_kek` and `wrap_key_region_1`.**
6. Return `Engine` holding only `Zeroizing<StateWrapKey>` (`wrap_key_region_2`)
   + `Zeroizing<PrefsHmacKey>` on the orchestrator; implementor must not retain
   `file_kek` in `WalletFile` steady-state fields (**0p** test).

**Disposition.** **Closed.** Lands in C5 (open path wiring) + C6 (`open_does_not_retain_file_kek`).
Review gate: any PR that caches `file_kek` on `WalletFile` past step 5 is a
**blast-radius regression**.

---

## §5.12 External lessons canvass (2026-05-27)

Second-pass review: historical wallet failures, OS discipline F5(b) depends on,
actor-model gaps at Stage 4, substrate precision, and governance. Disposition
table matches reviewer prioritization (**blocking PR 6** vs **FOLLOWUPS**).

### Blocking PR 6 (spec pins, §6 gates, or verified substrate)

| ID | Lesson | Disposition |
|----|--------|-------------|
| **L1** | **Slope / Solana 2022** — seed phrases in crash telemetry | Redaction discipline (type + subscriber) does **not** cover the **default Rust panic hook**. **C6:** `#[should_panic]` test: panic with `StateWrapKey` in scope; assert panic payload has **no** raw 32-byte key material (§6.2). Custom panic hook for wallet-RPC is **FOLLOWUPS** if product ships crash reporting. |
| **L2** | **Monero wallet2** — save during refresh serializes torn ledger | Stage 1: `LocalLedger::read()` guard before `save_state` (§6.1). Stage 4: **2d D4** snapshot immutability. |
| **L3** | **Actor mailbox OOM** — unbounded `SaveState` queues | **2d D3:** bounded mailbox, `try_send` back-pressure, save coalescing (last-write-wins). |
| **L4** | **Atomic Wallet 2023** — compromised release binary | Not trait-enforceable. **C1** module rustdoc cites [`SIGNING.md`](../SIGNING.md) as upstream defense. |
| **L5** | **Parity multisig 2017** — shared dependency blast radius | Stage 1: `Send`/`Sync` + cancellation-safety tests on `WalletFile` path (**2c** / C6) even though Stage 4 is where actor wrapping pays off. |
| **L6** | **KDF params tampering** | **Verified closed** — [`WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md) §2.1: `kdf_*` + `wrap_salt` are plaintext **AAD to the wrap AEAD** (`bytes[0..29)`). Tampering invalidates wrap decryption before region 1/2. Region 1 intentionally excludes wrap fields from AAD (rotation without re-encrypting region 1) — not a gap. |
| **L7** | **Android SecureRandom / nonce reuse** | Region-2 nonce: `OsRng` per save (`wallet_envelope.rs` `fresh_random_bytes`). **Not** `atomic_write_file` (raw bytes only). **C1** trait rustdoc pins CSPRNG nonce (Phase **0r**). |
| **L8** | **mlock / RLIMIT_MEMLOCK** | §3.7 + Phase **0s**: attempt mlock; warn on failure; honest F5(b) contingent claim. |
| **L9** | **HKDF `address` binding ambiguity** | **Verified closed** — HKDF doc: `addr` = 65-byte `expected_classical_address` from region 1 plaintext. |
| **L10** | **Actor crash supervisor** | **2d D5:** `stop`, no restart-and-continue; `ActorCrashed` on close path. |
| **L11** | **`ActorRef` leakage** | §6.2 grep: no `ActorRef<PersistenceEngine>` / persistence actor ref stored outside `Engine` field scope (Stage 4 gate; pin now for reviewer map). |

### FOLLOWUPS (not PR 6 blocking)

| ID | Lesson | Target | Work |
|----|--------|--------|------|
| **F1** | **Bitcoin Core** — wallet dir in cloud sync | **V3.1** | Platform markers: macOS `com.apple.metadata:com_apple_backup_excludeItem`, Linux `chattr +d`, Windows `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, `.nobackup` sentinel. `WalletFile::create` / implementor rustdoc pin (trait cites implementor responsibility). |
| **F2** | **Core dumps** — secrets in core files | **V3.1** | `prctl(PR_SET_DUMPABLE, 0)` (Linux) at wallet-RPC startup; §3.7 deployment property. |
| **F3** | **Argon2 stack copies** | **V3.1** | Cryptographer review: stack-resident intermediates in Argon2id path. |
| **F4** | **Rust + C++ dual open** | **V3.1** | Integration test: Rust `WalletFile` holds lock; C++ `wallet2` open same path → lock failure. |
| **F5** | **File metadata leaks** (size, mtime) | **V3.x** | Size-class padding; mtime obfuscation. |
| **F6** | **Empty-wallet fingerprint** | **V3.x** | Pad `.wallet` to size class. |
| **F7** | **Crypto agility / V4 migration** | **V3.x** | Format evolution path. |

### Cryptographer review bundle (add if not already on the four-target list)

- F5(b) session-key derivation ritual (**2h**).
- HKDF per-region correctness ([`WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md`](WALLET_FILE_FORMAT_V1_HKDF_REGION_DERIVATION.md)).
- Argon2 implementation stack hygiene (**F3**).
- PR 6 trait surface + WALLET_FILE_FORMAT §4.3 steady-state save model.

---

## §6 Review checklist (Round 3 — finalized)

Fill binding-check matrix at Round 2 segment **2g**. Mechanical gates:

- [ ] `cargo fmt --check`
- [ ] `cargo clippy -p shekyl-engine-core -p shekyl-engine-file --all-targets -- -D warnings`
- [ ] `cargo test -p shekyl-engine-core -p shekyl-engine-file`
- [ ] No new workspace deps without [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
- [ ] §3.3 benches: **none expected** for persistence hot path
- [ ] §8.2: spec amendment commit (C0) separate from consumer commits
- [ ] Grep: no `MockPersistence`
- [ ] Grep: steady-state `save_state` / `save_prefs` use sealing keys; `rotate_password` uses `Credentials`
- [ ] §6.2 F5(b) blast-radius greps (CI)
- [x] §6.3 HKDF prerequisite PR merged before implementation branch cuts (on `dev` post–`241a51ef6`)
- [ ] §6.3 atomic-write test suite green on prerequisite branch

### §6.2 F5(b) blast-radius grep gates (Round 3 **F-R3.6**)

Run on every PR 6 commit (or at minimum C6):

```bash
# No password material on steady-state save paths (trait + WalletFile)
rg 'save_state\s*\([^)]*password' rust/shekyl-engine-core rust/shekyl-engine-file
rg 'save_prefs\s*\([^)]*password' rust/shekyl-engine-core rust/shekyl-engine-file

# No long-lived file_kek on implementor state (field names; adjust if refactored)
rg 'file_kek' rust/shekyl-engine-file/src/handle.rs

# Sealing types: ZeroizeOnDrop at definition (manual read of type defs)
rg 'struct StateWrapKey|struct PrefsHmacKey' rust/

# No accidental wire serialization of sealing keys
rg 'derive.*Serialize.*StateWrapKey|StateWrapKey.*Serialize' rust/
rg 'derive.*Serialize.*PrefsHmacKey|PrefsHmacKey.*Serialize' rust/

# Redacted Debug (no raw key bytes in format strings)
rg 'impl Debug for StateWrapKey|impl Debug for PrefsHmacKey' rust/

# Stage 4: persistence actor ref must not escape Engine (§5.12 L11)
rg 'ActorRef.*Persistence|PersistenceActor' rust/shekyl-engine-core/src/engine/
```

**Panic-hook gate (§5.12 L1 — C6 test, not grep).** `#[should_panic]` test
constructs `StateWrapKey` from known bytes, panics with it in scope (e.g.
`panic!("{key:?}")` or `panic!("{}", …)`), captures `std::panic::catch_unwind`
payload or hook output, asserts **none** of the 32 key bytes appear. Documents
that default hook + `Debug` redaction are **insufficient** for production crash
reporting — custom hook required if Sentry-style telemetry is added.

**Reviewer interpretation:** `file_kek` may appear in **open** / **rotate**
functions and local temporaries; it must not appear as a field on
`WalletFile` / `WalletFileState` after **2h** lands. `rg file_kek` hits require
per-line disposition in PR review.

### §6.3 Implementation prerequisites (Round 3 **F-R3.7**, **F-R3.9**)

Before cutting `feat/stage-1-pr6-persistence-engine` from `dev`:

1. **HKDF amendment implementation PR** merged — `wrap_key_region_{1,2}`
   derivation in `shekyl-crypto-pq` / `shekyl-engine-file`; Tier-3 KAT vectors
   under `docs/test_vectors/WALLET_FILE_FORMAT_V1/` regenerated and CI-green.
   **Satisfied on `dev`** after `torvaldsl/wallet-hkdf-region-keys` (merged
   `47db00065`; this branch includes it via merge `241a51ef6`).
2. **`cargo test -p shekyl-engine-file atomic::`** — atomic write tests pass
   (see **2i G2** / **I1**).

### §6.1 Reviewer gate — flush paths, `Engine::close`, advisory lock

**Steady-state periodic flush (rewrite-era; PR 6 wires trait, may not land
caller yet):**

1. `Engine` holds session `StateWrapKey` + `PrefsHmacKey` from `open_full`.
2. Refresh / `on_flush` → `persistence.save_state(&state_key, &ledger).await`
   (and `save_prefs` when prefs change) — **no password**, no Argon2 per call
   after §4.3 / 0n amendment.

**`Engine::close` (PR 6 target):**

1. Refuse if `pending.outstanding() > 0`.
2. `LocalLedger::read()` → **snapshot** → `persistence.save_state(&state_key, &ledger).await`
   (snapshot must not mutate between read and serialize — **§5.12 L2**, **2d D4**).
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

**`change_password`:** `rotate_password` then `save_prefs`; returns
`ChangePasswordError` (**2b** / §5.10). **Refresh quiescence** required before
`close` when using `Arc` (**2a A1**). **Cancellation** table (**2a A2**).

---

## §7 Fenceposts — remaining rounds

| Round | Deliverable | Status |
|-------|-------------|--------|
| **Round 2** | Segments 2a–2d, 2g, 2h, 2i + §4/§6 | **Closed** |
| **Round 3** | §7.X + §6 gates + Round 2 amendments | **Closed** |
| **Phase 1** | C0–C7 on `feat/stage-1-pr6-persistence-engine` | **Ready** (after §6.3 prerequisites) |

### §7.1 Stage 1 closeout (do not conflate with PR 6 alone)

Update `V3_ENGINE_TRAIT_BOUNDARIES.md` §1 banner and FOLLOWUPS V3.0 inventory
only after **PR 6 + PR 7** land. Dedicated `STAGE_1_COMPLETION_AUDIT.md` is
**outstanding** (see FOLLOWUPS V3.0 closeout item).

---

## §7.X Phase 1 commit decomposition (Round 3 — closed)

**Deviation from template §8.2 eight-commit default:** Persistence has no
`SnapshotId`, no diagnostic enum, no `Signer`/`OutputSelector` secondary
traits, no `FaultInjecting` wrapper at V3.0 (bounded lens).

**Commit count (F-R3.1 resolved):** **Ten commits** — **C0**, **C1**, **C2a**,
**C2b**, **C2c**, **C3**, **C4**, **C5**, **C6**, **C7**. (Not "seven" — the
C2 subgroup is three commits, not one.)

**Build-at-every-commit (F-R3.2 — additive migration).** C2c **adds**
`save_state_with_key(&StateWrapKey, …)` alongside existing
`save_state(password, …)`; lifecycle callers migrate in **C5**; **C7** removes
the password-taking inherent method (no `[[deprecated]]` per pre-genesis
discipline — delete once migration is proven in C6).

**HKDF scope (F-R3.3).** C2c **does not** implement HKDF. Prerequisite PR lands
region-key derivation in `shekyl-crypto-pq` / envelope first. C2c only consumes
it for the additive API.

| Order | Commit | Scope | Phase 0 pins | Builds because |
|-------|--------|-------|--------------|----------------|
| 1 | **C0** | Doc-only: §2.6 shape; `PersistenceError`; `OpenError::Persistence`; `ChangePasswordError`; WALLET_FILE_FORMAT §4.3 cross-ref; this doc landed | 0a–0c, 0a′, 0j, 0m, 0l | Doc-only |
| 2 | **C1** | `StateWrapKey` / `PrefsHmacKey` types (`ZeroizeOnDrop`, redacted `Debug`); `traits/persistence.rs` + re-export; trait + module rustdoc (**0o**, G4 backup warning) | 0e, 0o | Types + trait, no callers yet |
| 3 | **C2a** | `WalletFileState` + `Mutex`; `rotate_password` → `&self` | 0d | Interior mutability only |
| 4 | **C2b** | `base_path()`; `save_as` internal paths unchanged | 0i | Mechanical |
| 5 | **C2c** | **Additive** `save_state_with_key(&StateWrapKey, &WalletLedger)` using prerequisite HKDF path; keep `save_state(password, …)` | 0n | Old callers unchanged |
| 6 | **C3** | `impl PersistenceEngine for WalletFile`; `PersistenceError` mapping | 0h | Trait wired to new method |
| 7 | **C4** | `Engine<…, P, F>`; field `persistence: F`; accessors | 0g | Engine holds `F`, may still call old inherent APIs |
| 8 | **C5** | `lifecycle.rs`: open ritual (**2h**); `close` / `change_password` via `F` + sealing keys; `OpenError::Persistence`; `ChangePasswordError` | 0f, 0p | Callers migrated |
| 9 | **C6** | Tests: **2c** matrix incl. stale-key + open ritual; no Mock | 0k | Full gate |
| 10 | **C7** | Remove `save_state(password, …)`; `CHANGELOG.md`; design doc implementation banner | — | Deletion after proof |

**§6 mapping:** `cargo fmt` / `clippy` every commit; **`cargo test -p shekyl-engine-core -p shekyl-engine-file`** at **C6** (and after C5 if C5 touches open).

### Round 3 findings log (disposition summary)

| ID | Finding | Disposition |
|----|---------|-------------|
| F-R3.1 | Commit count header vs table | Ten commits C0/C1/C2a–c/C3–C7 |
| F-R3.2 | C2c before C1 breaks build | Additive API; delete in C7 |
| F-R3.3 | C2c vs HKDF banner conflict | HKDF = prerequisite PR; C2c = API migration only |
| F-R3.4 | Phase 0o not in §4 | Row added (**0o**, **0p**) |
| F-R3.5 | R10 mapping undecided | `OpenError::Persistence` + `ChangePasswordError` (§5.10) |
| F-R3.6 | Missing F5(b) greps | §6.2 |
| F-R3.7 | HKDF prerequisite | §6.3 |
| F-R3.8 | Stale-key test | **2c** / C6 |
| F-R3.9 | Atomic durability test | Cite `atomic.rs` tests; crash injection FOLLOWUPS |
| F-R3.10 | G4 optional | Blocking in C1 rustdoc |

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
    /// Region-2 AEAD uses a fresh 24-byte nonce from the OS CSPRNG (`OsRng`)
    /// on every save — never counter-derived (see `seal_state_file` in
    /// `shekyl-crypto-pq`).
    ///
    /// `ledger` is a point-in-time snapshot; the implementor must not observe
    /// concurrent mutation after the caller captured it (§5.12 L2).
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
| Platform "do not back up" markers | §5.12 F1 | V3.1 — `WalletFile::create` |
| `prctl(PR_SET_DUMPABLE, 0)` | §5.12 F2 | V3.1 — wallet-RPC startup |
| Argon2 stack hygiene review | §5.12 F3 | V3.1 — cryptographer bundle |
| Rust + C++ advisory-lock cross-test | §5.12 F4 | V3.1 — rewrite-era dual stack |
| Wallet file size / mtime obfuscation | §5.12 F5–F6 | V3.x |
| Custom panic hook for crash telemetry | §5.12 L1 | Product adds Sentry-equivalent |

---

*Template:* [`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md).
*Spec:* [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md) §2.6, §2.8, §3, §6.4, §8.1–§8.3.
*Process:* [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
