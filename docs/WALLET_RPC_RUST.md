# The C++ `wallet2_ffi` Dispatcher (Phase 5 deletion target)

> **Scope note (2026-08-06, roadmap B1).** This document used to describe
> `rust/shekyl-engine-rpc`, the transitional Rust crate that wrapped C++
> `wallet2` over a C FFI facade and served it as JSON-RPC. **That crate is
> deleted.** What survives, and what this document now covers, is the C++
> side it wrapped: `src/wallet/wallet2_ffi.{h,cpp}`, still compiled into
> `libwallet` (`src/wallet/CMakeLists.txt`) and exercised by C++ unit tests,
> with no Rust consumer left. Deleting it is Phase 5's job
> ([`WALLET_REWRITE_PLAN.md`](design/WALLET_REWRITE_PLAN.md) §Phase 5).
>
> **This is not the wallet RPC reference.** The live, Shekyl-native wallet
> RPC is `rust/shekyl-wallet-rpc`, and its contract is
> [`docs/api/wallet_rpc.yaml`](api/wallet_rpc.yaml). Nothing below describes
> a surface a client should target.

## Why this document still exists

The dispatcher tabulated below is dead-ended but not yet removed, and its
method coverage is the checklist Phase 5 works against: every row is either
superseded by a `wallet_rpc.yaml` method, or rejected by design (Shekyl has
no accounts, no subaddresses, no integrated addresses, no raw tx-secret
export). Keeping the table until the C++ is gone is cheaper than
re-deriving it from `wallet2_ffi.cpp` at deletion time.

## FFI boundary design

The facade `rust/shekyl-engine-rpc` consumed is described here as-built,
because the C++ half is unchanged by the crate's deletion.

### JSON at the boundary

Complex types cross the FFI as JSON strings serialized by RapidJSON on the
C++ side. This avoided maintaining dozens of `repr(C)` structs and kept the
facade thin. Simple scalar returns (height, bool, version) use direct C
types.

### Opaque handle

```c
typedef struct wallet2_handle wallet2_handle;

wallet2_handle* wallet2_ffi_create(uint8_t nettype);
void wallet2_ffi_destroy(wallet2_handle* w);
```

The `wallet2_handle` wraps a `tools::wallet2` instance plus last-error
state.

### Generic dispatcher

```c
char* wallet2_ffi_json_rpc(wallet2_handle* w, const char* method, const char* params_json);
```

Routes an RPC method name to the corresponding wallet2 call. Returns a
heap-allocated JSON string (caller frees with `wallet2_ffi_free_string`).
On error, returns `NULL` and sets the handle's last-error fields.

### Thread safety

`wallet2` is not thread-safe. Callers were responsible for serializing
access; the deleted Rust wrapper did so with a `std::sync::Mutex` in
application state.

## Dispatcher method coverage

89 RPC methods from `wallet_rpc_server.h` are implemented in the
`wallet2_ffi_json_rpc` dispatcher (9 classical multisig methods were
removed; FROST multisig is Shekyl-native and never went through this
dispatcher):

> **Note (2026-05-19, Phase 2 of the Electrum-words removal series).**
> PR #58 deleted `restore_deterministic_wallet` and `get_languages`
> from the **C++ `wallet_rpc_server` HTTP JSON-RPC surface** (the
> `simplewallet`-style HTTP endpoint), but **not** from the
> `wallet2_ffi_json_rpc` dispatcher tabulated below. The FFI
> dispatcher (`src/wallet/wallet2_ffi.cpp:3477` / `:3511`) still
> routes both methods, and three dispatched methods —
> `create_wallet`, `restore_deterministic_wallet`, and
> `generate_from_keys` — still parse a `language` parameter. The
> dispatcher's defaulting and the Phase 1 hard-error gating differ
> per method (file references are `src/wallet/wallet2_ffi.cpp`):
>
> - `create_wallet`: dispatcher (`:3493`) defaults `language` to
>   `"English"`; the Phase 1 hard-error gate at
>   `wallet2_ffi_create_wallet` (`:315-321`) rejects any non-empty
>   value, so dispatcher callers must pass `language: ""`
>   explicitly to succeed.
> - `restore_deterministic_wallet`: dispatcher (`:3524`) defaults
>   `language` to `"English"`. There is **no** Phase 1 hard-error
>   gate on `wallet2_ffi_restore_deterministic_wallet`; the function
>   still routes through `crypto::ElectrumWords::words_to_bytes`
>   (`:423`) and is scheduled for outright deletion in Phase 3.
> - `generate_from_keys`: dispatcher (`:3543`) defaults `language`
>   to the empty string; the Phase 1 hard-error gate at
>   `wallet2_ffi_generate_from_keys` (`:490-496`) accepts that
>   default, so callers that omit `language` succeed.
>
> Phase 3 deletes both methods plus the `language` parameter from
> this surface as well; at that point the count drops to 87.
> Until then, this table is the source of truth for the FFI
> dispatcher's coverage. See
> [`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./completed/ELECTRUM_WORDS_REMOVAL_PLAN.md)
> Phase 2 / Phase 3 for the multi-surface sequencing.

| Category | Methods |
|----------|---------|
| Lifecycle | `create_wallet`, `open_wallet`, `close_wallet`, `stop_wallet`, `store`, `change_wallet_password` |
| Import | `restore_deterministic_wallet`, `generate_from_keys` |
| Balance/Address | `get_balance`, `get_address`, `get_height`, `get_address_index` |
| Accounts | `get_accounts`, `create_account`, `label_account`, `create_address`, `label_address` |
| Account tags | `get_account_tags`, `tag_accounts`, `untag_accounts`, `set_account_tag_description` |
| Subaddress | `set_subaddress_lookahead` |
| Transfers | `transfer`, `transfer_split`, `get_transfers`, `get_transfer_by_txid`, `incoming_transfers` |
| Sweeps | `sweep_all`, `sweep_single`, `sweep_dust`/`sweep_unmixable` |
| Offline TX | `sign_transfer`, `describe_transfer`, `submit_transfer`, `relay_tx` |
| Keys/Queries | `query_key`, `get_tx_key`, `sign`, `verify` |
| Proofs | `check_tx_key`, `get_tx_proof`, `check_tx_proof`, `get_reserve_proof`, `check_reserve_proof` |
| Payments | `get_payments`, `get_bulk_payments` |
| Address utils | `make_integrated_address`, `split_integrated_address`, `validate_address` |
| URI | `make_uri`, `parse_uri` |
| Address book | `get_address_book`, `add_address_book`, `edit_address_book`, `delete_address_book` |
| Export/Import | `export_outputs`, `import_outputs`, `export_key_images`, `import_key_images` |
| Freeze | `freeze`, `thaw`, `frozen` |
| Attributes | `set_attribute`, `get_attribute`, `set_tx_notes`, `get_tx_notes` |
| Refresh | `refresh`, `auto_refresh`, `rescan_blockchain`, `rescan_spent`, `scan_tx` |
| Mining | `start_mining`, `stop_mining` |
| Daemon | `set_daemon`, `set_log_level`, `set_log_categories` |
| Background sync | `setup_background_sync`, `start_background_sync`, `stop_background_sync` |
| Staking | `stake`, `unstake`, `get_staked_outputs`, `get_staked_balance`, `claim_rewards` |
| Fees | `estimate_tx_size_and_weight`, `get_default_fee_priority` |
| Meta | `get_version`, `get_languages` |

> **Note (2026-07-19, WI-RPC-1; extended 2026-07-24, WI-RPC-3).** The table
> above is the coverage of the **legacy `wallet2_ffi_json_rpc` dispatcher**,
> not of any shipping surface. The native Rust wallet RPC —
> `rust/shekyl-wallet-rpc`, contract in
> [`docs/api/wallet_rpc.yaml`](api/wallet_rpc.yaml) — serves these families
> natively, projected from the Engine with no wallet2 involvement:
>
> - **Receiving:** `create_payment_request`, `list_payment_requests`,
>   `make_uri`, `parse_uri`. Shekyl has no subaddresses or accounts; the
>   receive-attribution surface is the payment-request `rid` on the
>   `shekyl:` URI. The dispatcher's `get_accounts` / `create_address` /
>   subaddress rows above have no Shekyl-native equivalent by design.
> - **Fees:** `estimate_tx_size_and_weight`, `get_default_fee_priority`
>   (single-source projection of the engine's `predict_weight` byte model
>   and fee-converge fixpoint).
> - **Staking reads:** `get_staked_balance`, `get_staked_outputs`,
>   `staking_info` (authoritative staking read view; the action surface —
>   `unstake`, `claim_rewards` — remains engine-gated and RESERVED in the
>   contract).
> - **Proofs:** `get_tx_proof`, `check_tx_proof`, `get_reserve_proof`,
>   `check_reserve_proof` — DLEQ-based transaction and reserve proofs over
>   `rust/shekyl-proofs/`, Bech32m proof strings. The `check_*` pair is
>   wallet-less (daemon-only verification). The dispatcher's
>   `get_tx_key`/`check_tx_key` rows above have no Shekyl-native equivalent
>   by design: the proof surface supersedes raw tx-secret export.
> - **Lifecycle, reads, refresh, send, rescan:** Phase 4a/4b/4c.

## FROST multisig

FROST multisig never crossed this dispatcher. It is Shekyl-native, owned by
`rust/shekyl-multisig` (the ceremony / blob format) and reached through
`shekyl-engine-core`; the CI lane that compiles it under `--features
multisig` is `.github/workflows/multisig-feature.yml`. **DKG is not exposed
over RPC** — the `dkg-pedpop` crate's round message types do not implement
`serde::Serialize`/`Deserialize`, so DKG runs through the
`shekyl-engine-core` API with file-based message exchange (air-gap
compatible). See [`PQC_MULTISIG.md`](PQC_MULTISIG.md) for the ceremony flow.

## Sync driver

Background sync is driven by `shekyl-engine-core::Wallet::refresh`, which
runs the snapshot-merge-with-retry pattern: a snapshot of `(LedgerBlock,
LedgerIndexes)` is taken under a brief read borrow, the long-running
`produce_scan_result` async function fetches blocks and scans them
against the snapshot without holding any wallet borrow, and the
resulting [`ScanResult`](../rust/shekyl-engine-core/src/scan.rs) is
merged back into the wallet under `&mut self` via
`apply_scan_result_to_state`. Reorg detection (parent-hash compare,
`find_fork_point` walk) lives inside `produce_scan_result`; the
ledger-mutating rewind-then-apply runs atomically inside the merge.

The standalone `shekyl-scanner::sync::run_sync_loop` driver and its
`shekyl-scanner::rust-scanner` feature were retired in the Phase 2a
landing. The read-side JSON-RPC cache that outlived it —
`shekyl-engine-rpc::scanner_state`, behind that crate's separate
same-named `rust-scanner` feature — went with the crate at roadmap B1, so
no scanner-state cache sits between the Engine and an RPC reader any more.
See [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)
*"Retire `shekyl-scanner::sync::run_sync_loop` (Phase 2a/4b
boundary)"* (2026-04-27) for the rationale and
*"`Wallet::refresh` snapshot-merge-with-retry"* (2026-04-26) for the
driver contract.

## What Phase 5 removes

- `src/wallet/wallet2_ffi.{h,cpp}` — the facade and dispatcher above, now
  with no Rust consumer.
- `src/wallet/wallet2.{h,cpp}` and the C++ `wallet_rpc_server` — deleted
  wholesale by the Phase 5 single commit
  ([`WALLET_REWRITE_PLAN.md`](design/WALLET_REWRITE_PLAN.md) §Phase 5).
- The C++ `shekyl-wallet-rpc` binary name collision resolves at the same
  point: only the Rust binary remains.
