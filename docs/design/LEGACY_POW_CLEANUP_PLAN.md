# Legacy-PoW Cleanup Plan

| | |
|---|---|
| **Status** | EXECUTED — **Plan A** (RPC-payment-only this PR), on `chore/rpc-payment-deletion`. Scope surfaced for review; maintainer deferred the A/B + deferral decision to the implementer, so the Rule-19-cleanest cut (Plan A) was taken. During execution an orphaned Rust `RpcPrefs` persisted-prefs bucket surfaced; per the "delete in its entirety" mandate the maintainer approved folding it in as a self-contained Commit 4 (distinct persisted-schema validation surface, `19-validation-surface-discipline.mdc`). See §6 for the as-built commit list. |
| **Author** | (maintainer-reviewed) |
| **Date** | 2026-06-22 |
| **Parent** | [`RANDOMX_V2_PHASE3_PLAN.md`](./RANDOMX_V2_PHASE3_PLAN.md) (Phase 3 consensus cutover, landed PR #171 `6c3b86484`) |
| **FOLLOWUPS item** | "RandomX v2 Phase 3c / Phase 4 — PoW C-core + abstraction deletion" ([`docs/FOLLOWUPS.md`](../FOLLOWUPS.md)) — **this plan re-splits that cluster** |
| **Branch (proposed)** | `chore/rpc-payment-deletion` off `dev` (short-lived, `06-branching.mdc`) |

This plan governs the cleanup PR deferred by the RandomX v2 consensus cutover
(PR #171). PR #171 collapsed *consensus* block verification to RandomX v2 and
deleted `pow_cryptonight.cpp`, the `get_cryptonight_*` schema, the consensus
`RX_BLOCK_VERSION` guards, the longhash/block-id `202612` fossils, and the
dead-CryptoNight RPC branch. It deliberately left the *implementation* C and
several orphaned legacy elements in place. This plan dispositions each of those
leftovers and scopes the immediately-actionable subset into one PR.

---

## 1. Scope decision (the part needing authorization)

The task's "in-scope surface" lists four areas. Source verification (§3) shows
they do **not** share one validation surface (`19-validation-surface-discipline.mdc`)
and have hard dependency blockers. The rules-correct decomposition is:

### 1.1 IN SCOPE — this PR

| # | Unit | Why now |
|---|------|---------|
| **C1** | **Delete the RPC-payment subsystem in its entirety** — files + all daemon/wallet/rpc wiring + the two `CMakeLists`. | Truly orphaned dead code (no users; `RANDOMX_V2_RUST.md` §15 Phase-0 "delete in its entirety"). Single validation surface: wholesale dead-code removal, **zero consensus impact**. Removes the two surviving RPC-payment `RX_BLOCK_VERSION` guards and their `cn_slow_hash` / `rx_slow_hash` calls (`rpc_payment.cpp:237,245`, `wallet_rpc_payments.cpp:156,163`). |

That is the whole PR. **Verified magnitude (much larger than the task's "6
files + wiring" framing):** RPC-payment is woven into the daemon↔wallet RPC
wire contract and every daemon RPC handler. Source counts (2026-06-22):

| Surface | Evidence | Scale |
|---------|----------|-------|
| Wholesale-delete files | `rpc_payment.{cpp,h}`, `rpc_payment_costs.h`, `rpc_payment_signature.{cpp,h}`, `wallet_rpc_payments.cpp`, `wallet_rpc_helpers.h` | 7 files |
| Daemon per-handler pay-gate | `core_rpc_server.cpp` `CHECK_PAYMENT*` macro + invocations | **105 match-lines**, ~50+ handler sites |
| Wire contract collapse | `rpc_access_request_base`/`rpc_access_response_base` (`client`/`credits`/`top_hash`) → plain bases; ~30 endpoints inherit via `KV_SERIALIZE_PARENT` | ~30 endpoint structs in `core_rpc_server_commands_defs.h` |
| RPC-payment endpoints | `COMMAND_RPC_ACCESS_{INFO,SUBMIT_NONCE,PAY,TRACKING,DATA,ACCOUNT}` structs + handlers + dispatch maps (`core_rpc_server.{h,cpp}`, `core_rpc_ffi.cpp`) | 6 endpoints × (struct+decl+impl+map) |
| Wallet call-site wrappers | `wallet2.cpp` `pre_call_credits`/`req.client=get_client_signature()`/`check_rpc_cost(...)` | ~20 sites + 1 macro |
| Wallet proxy wrappers | `node_rpc_proxy.{cpp,h}` (ctor param, cache members, `get_rpc_payment_info`) | ~6 sites |
| Daemon CLI + glue | `daemon/command_server.cpp`, `command_parser_executor.{h,cpp}`, `rpc_command_executor.{h,cpp}`, `bootstrap_daemon.{h,cpp}`, `rpc_args.{h,cpp}`, `wallet_args.cpp`, `wallet_errors.h`, 2 `CMakeLists` | ~12 files |

Net: **~1000–1500 lines deleted across ~20 files**, including a daemon↔wallet
RPC wire-format change (in-tree clients only, pre-genesis → safe per
`60-no-monero-legacy.mdc` / `15-deletion-and-debt.mdc`). This is the inherent
size of "delete the RPC-payment subsystem in its entirety"; RPC-payment is a
known ~1500-line woven Monero subsystem.

**False-positive guards (do NOT delete):**
- `wallet_rpc_server.cpp:2041-2133` — local `wallet_rpc::payment_details rpc_payment`
  is a *received on-chain payment* (payment-id/amount), unrelated to pay-for-RPC.
- `RPC_TRACKER`/`RPCTracker` — dual-purpose (perf logging + `tracker.pay()`).
  Keep the tracker; remove only its payment members and the `CHECK_PAYMENT*`
  macros that call `tracker.pay()`.

**Execution mechanism (daemon):** delete the `check_payment()` member
(`core_rpc_server.cpp:~440-465`, calls `verify_rpc_payment_signature` +
`m_rpc_payment->pay()`), the `CHECK_PAYMENT*` macro definitions + all
invocations, the `m_rpc_payment` / `m_rpc_payment_allow_free_loopback` members
+ init, and collapse the wire bases. Keep `RPC_TRACKER` for timing.

### 1.2 RECOMMENDED DEFERRALS (with reasons + reopen criteria)

| # | Unit | Blocker / surface | Disposition |
|---|------|-------------------|-------------|
| **D1** | **CryptoNight implementation** — `src/crypto/slow-hash.c`, the `cn_slow_hash` / `cn_slow_hash_prehashed` / `cn_variant1_check` decls (`hash.h`, `hash-ops.h`), and the CryptoNight tests (`tests/hash/main.cpp`, `tests/crypto/cnv4-jit.c`, `tests/performance_tests/cn_slow_hash.*`). | **Blocked by live C++ KDF callers** that are *not* PoW: `src/crypto/chacha.h:69-80` (`generate_chacha_key`) and `src/cryptonote_basic/cryptonote_format_utils.cpp:1452,1460` (passphrase `encrypt_key`/`decrypt_key`). Replacing `cn_slow_hash`-KDF with argon2id is a **crypto-contract change touching secrets** → Rust, own design doc + review (`20-rust-vs-cpp-policy.mdc` "migration is a planning activity"; `36-secret-locality.mdc`). | Separate PR (KDF→Rust migration), *then* delete `slow-hash.c`. |
| **D2** | **PoW abstraction layer** — `pow_schema.h` (`IPowSchema`), `pow_registry.{h,cpp}`, the `rust/shekyl-consensus` crate, and the dead `shekyl_rust_init` / `shekyl_active_consensus_module` FFI exports. **Plus `RX_BLOCK_VERSION` `#define` removal** (see §1.3). | **Different validation surface** (consensus *dispatch* + Rust crate + FFI), not dead code: `get_pow_for_height` is **live** (`miner.cpp:582`, `cryptonote_tx_utils.cpp:886`). Collapsing it inlines RandomX into those consensus sites. `70-modular-consensus.mdc` + `19-validation-surface-discipline.mdc`. | Separate "PoW-abstraction collapse" PR. |
| **D3** | `shekyl_pow_randomx_v2_seedheight` FFI export + `shekyl-pow-randomx::consensus` module. | C `rx_seedheight` cleanly serves every caller while v1 stays (`RANDOMX_V2_PHASE3_PLAN.md` §5). | Stays deferred (task-directed). Reopens with D4. |
| **D4** | RandomX **v1** physical deletion — `rx-slow-hash.c`, the `rx_*` C surface, cncrypto RandomX linkage. | **HARD RETENTION** — rollback escape hatch (§4). | Reversion-clause-shaped (§4); reopens only when the v2 rollback window formally closes. |

### 1.3 The one flagged decision: `RX_BLOCK_VERSION` `#define`

Task item 3 assumed RPC-payment removal eliminates `RX_BLOCK_VERSION`'s "last
references," leaving only the bare `#define` (`hash-ops.h:95`) to delete.
**Source verification refutes that premise** — after RPC-payment is gone, two
*PoW-dispatch* references remain:

- `tests/core_tests/chaingen.cpp:465` — `if (blk.major_version >= RX_BLOCK_VERSION && diffic > 1)` (a Monero RandomX-activation guard in `fill_nonce`).
- `tests/unit_tests/mining_parity.cpp:104,137` — `RX_BLOCK_VERSION` as a sample block-version argument to `get_pow_for_height` (testing the **abstraction**).

Both remaining references live on the **PoW-dispatch / RandomX-from-genesis
validation surface**, which is **D2's** surface, not C1's dead-code surface.
`mining_parity.cpp` is *also* coupled to `get_pow_for_height`/`IPowSchema`
(deleted in D2). Per `19-validation-surface-discipline.mdc`, `RX_BLOCK_VERSION`
removal therefore belongs **with D2**, where `mining_parity.cpp` and
`chaingen.cpp` are touched **once** rather than twice across two PRs.

> **Decision (taken): Plan A.** The A/B choice was surfaced for review and
> deferred to the implementer; Plan A is the Rule-19-cleanest cut.
>
> - **A (taken):** This PR = **C1 only** (RPC-payment). `RX_BLOCK_VERSION`
>   `#define` removal folds into the D2 PoW-abstraction PR (shared
>   PoW-dispatch surface; `mining_parity.cpp` touched once).
> - **B (not taken):** C1 + a second commit removing the `#define` + rewriting
>   the two test sites now (incl. a consensus-test-adjacent change at
>   `chaingen.cpp:465`). Honors task item 3 verbatim but splits a single
>   validation surface across two PRs.

---

## 2. Dependency-ordered deletion DAG

```text
        ┌─────────────────────────────────────────────┐
        │ C1  Delete RPC-payment subsystem (THIS PR)   │
        │     - removes last wallet-tree PoW touchpoint │
        │     - removes 2 RX_BLOCK_VERSION guards       │
        │     - removes 2 rpc-payment cn/rx_slow_hash   │
        └───────────────┬──────────────────────────────┘
                        │ unblocks
        ┌───────────────┴───────────────┐
        ▼                               ▼
┌──────────────────────┐   ┌──────────────────────────────────┐
│ D2 PoW-abstraction    │   │ D1 KDF→Rust migration             │
│   collapse (sep. PR)  │   │   (chacha.h, format_utils)        │
│ - inline RandomX into │   │   then delete slow-hash.c +       │
│   miner/tx_utils      │   │   cn_slow_hash decls + CN tests   │
│ - del IPowSchema/     │   │   (sep. PR, crypto-contract,      │
│   pow_registry        │   │    own design doc)                │
│ - del shekyl-consensus│   └──────────────────────────────────┘
│ - del RX_BLOCK_VERSION│
│   (#define + 2 tests) │
│ - del dead FFI inits  │
└───────────┬───────────┘
            │ (much later, gated)
            ▼
┌────────────────────────────────────────────┐
│ D4 RandomX v1 physical deletion             │
│    + D3 shekyl_pow_randomx_v2_seedheight     │
│    ONLY when rollback window closes (§4)     │
└────────────────────────────────────────────┘
```

C1 has **no** in-PR prerequisites and blocks nothing it must complete in the
same PR. D1, D2, D3/D4 are strictly downstream and out of this PR's scope.

---

## 3. Source-verification evidence

### 3.1 RPC-payment is the sole wallet-tree PoW touchpoint (C1 is unblocked)

`cn_slow_hash` / `rx_slow_hash` call sites that die with RPC-payment:

| Site | Disposition |
|------|-------------|
| `src/rpc/rpc_payment.cpp:245` (`cn_slow_hash`) | deleted with file |
| `src/wallet/wallet_rpc_payments.cpp:163` (`cn_slow_hash`) | deleted with file |
| `src/rpc/rpc_payment.cpp:237` (`RX_BLOCK_VERSION` guard) | deleted with file |
| `src/wallet/wallet_rpc_payments.cpp:156` (`RX_BLOCK_VERSION` guard) | deleted with file |

### 3.2 Why `slow-hash.c` cannot be deleted in this PR (D1 blocker)

Live, non-PoW `cn_slow_hash` callers remain after RPC-payment is gone:

| Site | Role |
|------|------|
| `src/crypto/chacha.h:69,71,78,80` | `generate_chacha_key` — wallet password→key KDF (legacy C++ wallet) |
| `src/cryptonote_basic/cryptonote_format_utils.cpp:1452,1460` | passphrase hashing in `encrypt_key`/`decrypt_key` (also does scalar arithmetic on secrets) |

These are live in the C++ legacy wallet keystore. Migrating them off
`cn_slow_hash` (to argon2id, per the maintainer's note that Shekyl KDF is
argon2id+bip39 in Rust) is a crypto-contract change requiring its own design
doc and review cycle. Until then `slow-hash.c` + the `cn_slow_hash` decls + the
CryptoNight tests stay.

### 3.3 Why the PoW abstraction is a separate surface (D2)

`get_pow_for_height` / `IPowSchema` are **live consensus dispatch**, not dead
code:

| Site | Role |
|------|------|
| `src/cryptonote_basic/miner.cpp:582-583` | `get_pow_for_height(...).prepare_miner_thread(...)` |
| `src/cryptonote_core/cryptonote_tx_utils.cpp:886,902` | `get_pow_for_height(...).hash(...)` in `get_block_longhash` |
| `tests/unit_tests/mining_parity.cpp:103,104,136-137` | dispatch tests |

The `rust/shekyl-consensus` crate is reachable only via `shekyl_rust_init` /
`shekyl_active_consensus_module`, which have **no C++ call sites** (dead-ish
scaffolding, `70-modular-consensus.mdc`). Deleting all of this is the
"abstraction collapse" surface: it edits consensus-dispatch sites and removes a
Rust crate + FFI exports — distinct from C1's RPC dead-code removal.

---

## 4. RandomX v1 retention boundary (HARD CONSTRAINT)

RandomX **v1** is retained as a consensus rollback escape hatch. This PR (and
D1/D2/D3) **must not** delete or alter:

- `src/crypto/rx-slow-hash.c`
- The `rx_slow_hash` / `rx_seedheight` / `rx_seedheights` /
  `rx_slow_hash_allocate_state` / `rx_set_main_seedhash` C surface
  (`src/crypto/hash-ops.h`)
- The `cncrypto` ↔ RandomX C linkage

v1 stays **compiled and linkable** so a rollback is a small diff. The current
FOLLOWUPS cluster bundles `rx-slow-hash.c` deletion *with* CryptoNight (item 2);
this plan **re-splits** it (§8) and rewrites the v1 entry as a reversion clause
(`21-reversion-clause-discipline.mdc`):

> **v1 kept for rollback. Reopen v1 deletion (D4) only when the v2 rollback
> window formally closes** — concretely, after **N consecutive stable releases
> on RandomX v2 with no rollback invocation** (N to be ratified; suggest 2–3
> tagged stable releases) — at which point `rx-slow-hash.c`, the `rx_*` C
> surface, the cncrypto linkage, *and* the deferred D3 export
> (`shekyl_pow_randomx_v2_seedheight`) land together.

---

## 5. Rollback note

- **This PR (C1)** is consensus-inert: RPC-payment is an RPC access-control
  feature, not block validation. Reverting C1 = `git revert` of the deletion
  commits; no chain/state implications.
- **RandomX v1 rollback** (the reason v1 is retained) is unaffected by this PR.
  Because C1 touches nothing in `rx-slow-hash.c` / the `rx_*` surface / cncrypto
  linkage, the v1→consensus path remains a small, self-contained diff after this
  PR lands. §4 is the invariant the rollback depends on.

---

## 6. Commit plan (Plan A)

One logical unit per commit; build-green at every commit; grep-anchored audit
table per commit in the message (`50-testing.mdc`, `90-commits.mdc`).

**Build-green seam.** The shared contract is `core_rpc_server_commands_defs.h`
(the `COMMAND_RPC_ACCESS_*` structs), consumed by *both* the daemon
(`core_rpc_server`) and the wallet (`node_rpc_proxy`). Removing those structs is
only build-green once **no consumer references them**. Therefore the order is
**wallet-side first** (drops the wallet's references; the structs stay,
daemon-built unaffected), **then daemon-side** (removes the daemon's references
*and* the now-orphaned structs + the wholesale files):

0. **`docs: add legacy-PoW cleanup plan`** — this plan doc.
1. **`wallet: delete RPC-payment client subsystem`** — remove all RPC-payment
   from `wallet2.{cpp,h}`, `wallet2_ffi.cpp`, `wallet_rpc_server.{h,cpp}`,
   `wallet_rpc_helpers.h`, `node_rpc_proxy.{h,cpp}`, `wallet_args.cpp`,
   `wallet_errors.h`; wholesale-delete `src/wallet/wallet_rpc_payments.cpp`;
   drop it from `src/wallet/CMakeLists.txt`. Gate: `shekyl-wallet-rpc` +
   `shekyld` build green.
2. **`rpc/daemon: delete RPC-payment server subsystem`** — wholesale-delete
   `src/rpc/rpc_payment.{cpp,h}`, `src/rpc/rpc_payment_costs.h`,
   `src/rpc/rpc_payment_signature.{cpp,h}`; remove RPC-payment from
   `core_rpc_server.{h,cpp}`, `core_rpc_ffi.cpp`,
   `core_rpc_server_commands_defs.h` (the `COMMAND_RPC_ACCESS_*` structs),
   `bootstrap_daemon.{h,cpp}`, `rpc_args.{h,cpp}`, `daemon/command_server.cpp`,
   `daemon/command_parser_executor.{h,cpp}`,
   `daemon/rpc_command_executor.{h,cpp}`; drop the files from
   `src/rpc/CMakeLists.txt`. Gate: `shekyld` + `shekyl-wallet-rpc` build green.

> The exact boundary between commits 1 and 2 is dependency-driven (each must
> compile); the split may shift slightly at execution if a shared header forces
> it. The **invariant** is: each commit builds green, and no commit bundles
> unrelated changes. If commits 1 and 2 cannot be made independently
> build-green (e.g. a tighter header coupling than the survey shows), they
> collapse to a single **`rpc/wallet: delete RPC-payment subsystem`** commit —
> still one logical unit (one subsystem), per `90-commits.mdc` scope rule.

Plan A adds **no** `RX_BLOCK_VERSION` commit (deferred to D2).

### 6.1 As-built commit list (`chore/rpc-payment-deletion`)

The build-green seam split the daemon-side work into a wiring commit and a
wire-contract commit (collapsing `rpc_access_*_base` + deleting
`rpc_payment_signature.{cpp,h}` / `rpc_payment_costs.h` is a distinct logical
unit from removing the daemon handler wiring), and the orphaned Rust prefs
bucket became its own commit (separate persisted-schema validation surface):

0. `docs: add legacy-PoW cleanup plan (RPC-payment deletion)` + `docs: record
   verified RPC-payment audit in cleanup plan` — this plan doc.
1. `wallet: remove RPC-payment client subsystem` — wallet-side client wiring +
   `wallet_rpc_payments.cpp` / `wallet_rpc_helpers.h` deletion. Build-green.
2. `rpc: remove daemon-side RPC-payment subsystem` — daemon handler wiring,
   `check_payment`/`CHECK_PAYMENT*`, `COMMAND_RPC_ACCESS_*` handlers + FFI
   dispatch, CLI command, `bootstrap_daemon` params, `rpc_payment.{cpp,h}`
   deletion; plus the Rust `shekyl-daemon-rpc` restricted-method names and the
   Python framework wrappers. Build-green.
3. `rpc: collapse RPC-payment wire contract` — `rpc_access_*_base` →
   `rpc_request_base`/`rpc_response_base`, delete the `COMMAND_RPC_ACCESS_*`
   structs, delete `rpc_payment_signature.{cpp,h}` + `rpc_payment_costs.h`,
   `CORE_RPC_VERSION_MINOR` 15→16, update `src/rpc/CMakeLists.txt`. Build-green.
4. `wallet-prefs: remove orphaned RPC-payment prefs bucket` — delete `RpcPrefs`
   from `shekyl-engine-prefs`, `PREFS_SCHEMA_VERSION` 2→3, update
   `docs/WALLET_PREFS.md`. (Maintainer-approved scope addition; see Status.)
5. `docs: …` (this commit) — CHANGELOG `### Removed` entry, FOLLOWUPS cluster
   re-split (v1 reversion clause), and this plan's as-built update.

---

## 7. Reviewer map

| Class | Sites | Reviewer focus |
|-------|-------|----------------|
| **Wholesale deletion** | `rpc_payment.{cpp,h}`, `rpc_payment_costs.h`, `rpc_payment_signature.{cpp,h}`, `wallet_rpc_payments.cpp` | Confirm no surviving references; files truly orphaned. |
| **Mechanical wiring removal** | daemon `command_*` / `rpc_command_executor`; `core_rpc_server*`, `core_rpc_ffi`, `bootstrap_daemon`, `rpc_args`; `wallet2*`, `wallet_rpc_server*`, `node_rpc_proxy*`, `wallet_args`, `wallet_rpc_helpers.h`, `wallet_errors.h`; 2 `CMakeLists`. | No behavior change to non-RPC-payment paths; RPC command table, CLI args, and error enums cleanly removed; build green. |
| **Consensus-affecting** | **NONE in Plan A.** | RPC-payment is not block validation; parity/mining gates untouched. |
| **Consensus-test-adjacent** | *(Plan B only)* `chaingen.cpp:465` rewrite. | RandomX-from-genesis alignment; confirm core-test nonce-finding still mines (diffic-1 genesis-identity path unaffected). |

---

## 8. FOLLOWUPS re-split (replaces the current cluster)

The current cluster's **item 2 is wrong** — it bundles `rx-slow-hash.c` (v1,
**retained**) with `slow-hash.c` (CryptoNight) deletion. Proposed replacement
structure (full text written in the docs commit, `91-documentation-after-plans.mdc`):

1. **Delete the RPC-payment subsystem** — **this PR** (C1). Target V3.0.
2. **PoW-abstraction collapse** — `IPowSchema`/`pow_registry`/`pow_schema.h`,
   inline RandomX into `miner.cpp`/`cryptonote_tx_utils.cpp`, delete
   `rust/shekyl-consensus` + dead `shekyl_rust_init`/`shekyl_active_consensus_module`
   FFI, delete `RX_BLOCK_VERSION` `#define` (+ `chaingen`/`mining_parity` test
   rewrites). Unblocked by (1). Target V3.0.
3. **Wallet KDF → Rust (argon2id) migration**, then **delete CryptoNight
   `slow-hash.c`** + `cn_slow_hash` decls + CryptoNight tests. Crypto-contract
   change; own design doc. Target V3.0.
4. **RandomX v1 retention (reversion clause)** — `rx-slow-hash.c`, `rx_*`
   surface, cncrypto linkage, **and** the `shekyl_pow_randomx_v2_seedheight`
   export are **kept**; reopen for deletion only when the v2 rollback window
   formally closes (§4). Not target-versioned for deletion; this is a *retention*
   entry, not a deletion-debt entry.

---

## 9. Verification gates (before "done")

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --workspace`
- C++ `unit_tests` (esp. `tests/unit_tests/mining_parity.cpp` — RandomX-only
  schema + genesis-identity gate must stay green)
- `tests/randomx_v2_parity/randomx_v2_full_parity.cpp` (Hole-1 release gate) —
  still passes
- Persisted-schema snapshot check (`42-serialization-policy.mdc`)
- **RandomX v1 still compiles/links** (rollback hatch intact, §4)

---

## 10. What this plan does NOT do

- Does not delete or touch RandomX v1 (`rx-slow-hash.c`, `rx_*`, cncrypto
  linkage). §4.
- Does not delete `slow-hash.c` / `cn_slow_hash` / CryptoNight tests (D1 blocker).
- Does not delete the PoW abstraction or `rust/shekyl-consensus` (D2 surface).
- Does not add `shekyl_pow_randomx_v2_seedheight` (D3, deferred).
- Does not push or open a PR without explicit per-action authorization
  (`06-branching.mdc`).
