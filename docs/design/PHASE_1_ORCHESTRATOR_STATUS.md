# Phase 1 orchestrator — gap-audit status

Audited at `dev` tip, 2026-06-10; matrix updated through PR 5
(`feat/phase1-closeout`) the same day. This is the done/open matrix for
the Phase 1 deliverables in `WALLET_REWRITE_PLAN.md`, read with the
binding naming decision applied (`shekyl-engine-core::Engine<S>`, not
`shekyl-wallet-core::Wallet` — `V3_WALLET_DECISION_LOG.md` 2026-04-27).

**Phase 1 status: CLOSED.** Every deliverable is done or explicitly
blocked with a reversion clause (View/HW lifecycle bodies, FOLLOWUPS
V3.0 queue).

## Phase 0 half-day gate — passed

| Gate item | Evidence |
|---|---|
| Vendor state | `docs/MONERO_OXIDE_VENDOR_STATUS.md` present and current |
| shekyld prerequisites | `docs/SHEKYLD_PREREQUISITES.md` — regtest caveats, `get_fee_estimates` audited (PR 0.3) |
| FOLLOWUPS V3.1+ absorption table | `docs/FOLLOWUPS.md` §"V3.1+ wallet-rewrite absorption" index table present |
| Cross-cutting locks | `docs/V3_WALLET_DECISION_LOG.md` — locks stand; supersessions are dated entries |
| Un-merged upstream | No Phase 1 API change forced; vendor deltas are crypto-level only |

## Gap matrix

Status legend: **done** (landed with tests), **partial** (landed,
follow-up named), **open** (work item), **blocked** (deferred with
documented blocker + reversion clause).

### Core type & lifecycle

| Deliverable | Status | Evidence |
|---|---|---|
| `Engine<S>` composition documented; no god-object drift | done | `rust/shekyl-engine-core/src/engine/mod.rs` module docs: field table, cross-cutting locks honored, seven-generic production shape `Engine<S, D, L, E, R, P, F>` |
| `open_view_only` / `open_hardware_offload` real bodies | blocked | Stubs return `OpenError::CapabilityNotYetImplemented` (`engine/lifecycle.rs:647`, `:666`). Blocker: `shekyl-crypto-pq` has no view-only / hardware-offload account constructors (`rust/shekyl-crypto-pq/src/account.rs` exposes full-key derivation only). Tracked in `FOLLOWUPS.md` (V3.0 wallet-stack queue). Reopens when the constructors land; re-evaluation shape: lifecycle PR implementing real bodies + capability-dispatch tests |
| `change_password` integration tests driving `WalletFile::rotate_password` on disk (FULL) | done | `change_password_round_trips_via_independent_wallet_file_open` and `change_password_with_new_kdf_rewrites_envelope_header` (`engine/lifecycle.rs`, after `:1310`) verify the rotated envelope against an independently constructed `WalletFile::open` and the rewritten KDF header via `inspect_keys_file`. FULL only; ViewOnly / HW extension rides the capability-dispatch commit per the reshaped `FOLLOWUPS.md` entry |

### Refresh & scan

| Deliverable | Status | Evidence |
|---|---|---|
| `RefreshHandle` cancel-on-drop, single-flight | done | `engine/refresh.rs`: `cancel()` (`:538`), tests `drop_fires_cancel_token` (`:2463`), `idempotent_cancel_is_no_op` (`:2478`), `mem_forget_does_not_fire_cancel` (`:2504`). Single-flight is enforced by the in-flight producer slot returning `RefreshError::AlreadyRunning` (`:1244`), not by a `&mut self` borrow — `start_refresh` takes `Arc<RwLock<Self>>` (`:1256`) per the landed PR 4 design; the plan's original `&mut self` phrasing is superseded by that design doc |
| `apply_scan_result` strict contract tests (`MalformedScanResult`) | done | `engine/merge.rs:346` rejection site; 23 tests in the module |
| Async refresh path uses orchestrator merge post-pass | done | STAGE_1_COMPLETION_AUDIT P1 closure (2026-05-30): trait-side merge removed, async path routes through `Engine::apply_scan_result` |

### Pending tx

| Deliverable | Status | Evidence |
|---|---|---|
| Chain-state pinning on submit (`TooOld`, `ChainStateChanged`) | done | `engine/pending.rs:669`, `:678`; tests at `:1103` ff. |
| `close` refuses outstanding reservations | done | `engine/lifecycle.rs:1052–1054` (`OpenError::OutstandingPendingTx { count }`); test `close_with_outstanding_reservation_returns_outstanding_pending_tx` (`:1359`) |

### Public query surface

| Deliverable | Status | Evidence |
|---|---|---|
| `Engine::balance()` or documented pattern | done (pattern documented) | No `Engine::balance()` by design: a thin wrapper would freeze a signature before the Phase 2 filtered-query design settles. The pattern (`engine.ledger()` guard → `guard.ledger.balance(guard.ledger.height())` via `shekyl_scanner::LedgerBlockExt`) is documented in `engine/mod.rs` §"Query surface (Phase 1 disposition)". Reopen at Phase 2 ops (plan §History/Balance) |
| `Engine::transfers(filter)` or equivalent | done (pattern documented) | Slice access `engine.ledger().ledger.transfers()` (`rust/shekyl-engine-state/src/ledger_block.rs:247`) documented in the same `engine/mod.rs` section. Filtered query API is Phase 2 (plan §History) |
| `Engine::primary_address()` via key handle | done | `Engine::primary_address()` (`engine/mod.rs`, accessor block) assembles `ShekylAddress` from the `KeyActor`'s cached public projection (`KeyEngine::account_public_address`, sync, no actor round-trip) plus the cached network; `ShekylAddress` re-exported from `shekyl-engine-core`. Round-trip test `primary_address_renders_and_round_trips` (`engine/lifecycle.rs`). Phase 2c expands the receive surface |

### Logging (absorbed from V3.2 FOLLOWUPS)

| Deliverable | Status | Evidence |
|---|---|---|
| `shekyl_log_install_tracing_forwarder` in `rust/shekyl-logging/src/ffi.rs` | done | Implemented per decision log 2026-04-25 + single-image mechanism amendment 2026-06-10; `SHEKYL_LOG_ERR_ALREADY_INSTALLED = -12` allocated. State-machine integration test (`tests/tracing_forwarder.rs`) + C-harness arms (`tests/c_ffi.rs`) |
| shekyld calls it after `shekyl_log_init_*` / `mlog_configure` | done | `src/daemon/main.cpp` immediately after `mlog_configure`; declaration in `src/shekyl/shekyl_log.h` |
| Idempotent `ALREADY_INSTALLED` / `NOT_INITIALIZED` codes | done | One-shot pin; pre-init failure does not consume the pin (retry-after-init works) |

Implementation note (resolved): the link audit found the pre-change
`shekyld` carried **two** `tracing-core` `GLOBAL_DISPATCH` copies (one
per Rust staticlib image), so the original cross-image "forwarder
install" framing was unimplementable as specified. Landed shape is the
single-Rust-image contract: `shekyl-daemon-rpc` depends on
`shekyl-logging` (one merged image), the daemon force-loads
`libshekyl_daemon_rpc.a` (`SHEKYL_DAEMON_RPC_WHOLE_ARCHIVE`,
`cmake/BuildRust.cmake`), and a post-link `nm` gate on the `daemon`
target asserts exactly one dispatcher. See decision log 2026-06-10.

### Tests & docs

| Deliverable | Status | Evidence |
|---|---|---|
| Lifecycle round-trips, password rotation, network mismatch, capability dispatch | done | `engine/lifecycle.rs` test module (20 tests): rotation (`:1273`), network mismatch (`:1248` ff.), state-file recovery, capability stubs |
| `RefreshHandle` cancel semantics | done | see Refresh & scan above |
| Close with outstanding `PendingTx` → typed error | done | see Pending tx above |
| `WALLET_REWRITE_PLAN.md` frontmatter todos + Phase 1 naming | done | Frontmatter `phase0_closeout` and `phase1_domain_model` marked completed with `Engine` naming; global naming-supersession banner after the plan title; Phase 1 section closeout banner pointing here; Gap-section orchestrator bullet closed; Phase 2a "remain pending Phase 1" prose corrected (orchestrator methods landed) |
| `CHANGELOG.md` entry for Phase 1 closeout | done | "Unreleased / Added — engine: Phase 1 orchestrator closeout" entry |

## Close-out sequence (per 06-branching.mdc sizing)

1. **PR 1 — this document.** Gap audit, doc-only.
2. **PR 2 — tracing forwarder.** Landed (`feat/phase1-closeout`):
   `shekyl-logging::ffi` `shekyl_log_install_tracing_forwarder` (+ `-12`
   code, tests), `shekyl-daemon-rpc` → `shekyl-logging` dependency
   (single-image), daemon force-load + `nm` gate, `shekyl_log.h`
   declaration, `src/daemon/main.cpp` call site. Closes the absorbed
   V3.2 FOLLOWUPS item per decision log 2026-06-10.
3. **PR 3 — `change_password` integration test.** Landed
   (`feat/phase1-closeout`): drives `WalletFile::rotate_password` on
   disk for FULL; verifies against an independent `WalletFile::open`
   and the rewritten KDF header. Closes the FOLLOWUPS V3.0 item for
   FULL capability.
4. **PR 4 — public query accessors.** Landed (`feat/phase1-closeout`):
   thin `Engine::primary_address()`; `ledger()`-based balance/transfers
   pattern documented in `engine/mod.rs`. No Phase 2 wrapper scope.
5. **PR 5 — doc closeout.** Landed (`feat/phase1-closeout`):
   `WALLET_REWRITE_PLAN.md` frontmatter + naming reconciliation,
   FOLLOWUPS absorption marks, `CHANGELOG.md` Phase 1 entry. **Phase 1
   is closed**; the only carried residue is the View/HW lifecycle
   blocker below.

PRs 2 and 3 are independent and must not be bundled. View/HW lifecycle
bodies stay blocked on `shekyl-crypto-pq` constructors and are **not**
part of this close-out; the FOLLOWUPS entry carries the reversion
clause.
