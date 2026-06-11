# Phase 1 orchestrator — gap-audit status

Audited at `dev` tip, 2026-06-10. This is the done/open matrix for the
Phase 1 deliverables in `WALLET_REWRITE_PLAN.md`, read with the binding
naming decision applied (`shekyl-engine-core::Engine<S>`, not
`shekyl-wallet-core::Wallet` — `V3_WALLET_DECISION_LOG.md` 2026-04-27).

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
| `change_password` integration tests driving `WalletFile::rotate_password` on disk (FULL) | open | `change_password_rewraps_envelope_then_reopen_uses_new_password` (`engine/lifecycle.rs:1273`) verifies rotation via `Engine::open_full` only. The `FOLLOWUPS.md` V3.0 item asks for verification against an independently constructed `WalletFile::open` call. Implementable now — PR 3 below |

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
| `Engine::balance()` or documented pattern | partial | No `Engine::balance()`. Pattern exists: `engine.ledger()` → `LedgerReadGuard` derefs to `&WalletLedger`; balance computed via `shekyl-scanner`'s `LedgerBlockExt::balance(current_height)` (`rust/shekyl-scanner/src/ledger_ext.rs:185`). Bench helpers (`engine_balance_for_bench`) demonstrate the path. Thin orchestrator wrappers are Phase 2 ops per plan §Phase 2 (History/Balance); Phase 1 disposition: document the pattern (this doc + `engine/mod.rs`), defer wrappers to Phase 2 |
| `Engine::transfers(filter)` or equivalent | partial | Slice access exists: `engine.ledger().ledger.transfers()` (`rust/shekyl-engine-state/src/ledger_block.rs:247`). Filtered query API is Phase 2 (plan §History) |
| `Engine::primary_address()` via key handle | open | `KeyEngineHandle` caches `AccountPublicAddress` and serves it sync via `KeyEngine::account_public_address` (`engine/key_actor.rs`), but the trait is `pub(crate)` and `Engine` exposes no public accessor — binaries currently have no way to read the wallet address. Thin `Engine::primary_address()` accessor is in Phase 1 scope (Phase 2c expands). PR 4 below |

### Logging (absorbed from V3.2 FOLLOWUPS)

| Deliverable | Status | Evidence |
|---|---|---|
| `shekyl_log_install_tracing_forwarder` in `rust/shekyl-logging/src/ffi.rs` | open | Decision logged (`V3_WALLET_DECISION_LOG.md` 2026-04-25, `:1795`) with exact signature; not implemented. Error-code table in `ffi.rs` ends at `-11`; `SHEKYL_LOG_ERR_ALREADY_INSTALLED` to be allocated `-12` |
| shekyld calls it after `shekyl_log_init_*` / `mlog_configure` | open | Call site: `src/daemon/main.cpp` after `mlog_configure` (`:336`); declaration added to `src/shekyl/shekyl_log.h` |
| Idempotent `ALREADY_INSTALLED` / `NOT_INITIALIZED` codes | open | `SHEKYL_LOG_ERR_NOT_INITIALIZED = -9` exists; install-state machine to be added |

Implementation note: `rust/shekyl-daemon-rpc/Cargo.toml` depends on
`tracing` but **not** on `shekyl-logging` — its staticlib image carries a
dispatcher with no subscriber, which is the "tracing silently dropped"
bug the forwarder closes. Whether the final C++ link deduplicates
`tracing-core` across `libshekyl_logging.a` / `libshekyl_daemon_rpc.a` /
`libshekyl_ffi.a` is verified at the CMake build, not assumed; the
forwarder PR must build `shekyld` as part of its test gate.

### Tests & docs

| Deliverable | Status | Evidence |
|---|---|---|
| Lifecycle round-trips, password rotation, network mismatch, capability dispatch | done | `engine/lifecycle.rs` test module (20 tests): rotation (`:1273`), network mismatch (`:1248` ff.), state-file recovery, capability stubs |
| `RefreshHandle` cancel semantics | done | see Refresh & scan above |
| Close with outstanding `PendingTx` → typed error | done | see Pending tx above |
| `WALLET_REWRITE_PLAN.md` frontmatter todos + Phase 1 naming | open | Frontmatter `phase1_domain_model` still `pending` and still says `shekyl-wallet-core::Wallet`; body `:537` says Phase 2a orchestrator methods "remain pending Phase 1" — stale (landed as `Engine::refresh` / `build_pending_tx` / …). PR 5 below |
| `CHANGELOG.md` entry for Phase 1 closeout | open | PR 5 below |

## Close-out sequence (per 06-branching.mdc sizing)

1. **PR 1 — this document.** Gap audit, doc-only.
2. **PR 2 — tracing forwarder.** `shekyl-logging::ffi`
   `shekyl_log_install_tracing_forwarder` (+ `-12` code, unit tests),
   `shekyl_log.h` declaration, `src/daemon/main.cpp` call site,
   `shekyl-daemon-rpc` → `shekyl-logging` dependency if the link audit
   requires it. Closes the absorbed V3.2 FOLLOWUPS item.
3. **PR 3 — `change_password` integration test.** Drive
   `WalletFile::rotate_password` on disk for FULL; verify against an
   independent `WalletFile::open`. Closes the FOLLOWUPS V3.0 item.
4. **PR 4 — public query accessors.** Thin `Engine::primary_address()`;
   document the `ledger()`-based balance/transfers pattern in
   `engine/mod.rs`. No Phase 2 wrapper scope.
5. **PR 5 — doc closeout.** `WALLET_REWRITE_PLAN.md` frontmatter +
   naming reconciliation, FOLLOWUPS absorption marks, `CHANGELOG.md`
   Phase 1 entry.

PRs 2 and 3 are independent and must not be bundled. View/HW lifecycle
bodies stay blocked on `shekyl-crypto-pq` constructors and are **not**
part of this close-out; the FOLLOWUPS entry carries the reversion
clause.
