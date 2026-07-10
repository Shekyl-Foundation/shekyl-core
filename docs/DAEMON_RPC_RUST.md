# Daemon RPC: Rust/Axum Migration

Phase 1 of the epee-to-Rust migration replaces the daemon's HTTP transport layer
with Axum while keeping all handler logic in C++. **Phase 1 is complete:** the
epee HTTP listener, `--no-rust-rpc`, and inbound daemon `--rpc-login` /
`--rpc-ssl*` surface are deleted. Phase 2 replaces epee KV serialization in the
FFI dispatch path.

## Architecture

```
  Client
    │
    ▼
  Axum (Rust)            ◀─ HTTP transport, CORS (default-deny), body limits, route dispatch
    │
    ▼
  CoreRpc (Rust)         ◀─ FFI wrapper, spawn_blocking for C++ calls
    │
    ▼ C ABI
  core_rpc_ffi.cpp       ◀─ Dispatch tables: URI → handler, epee serialization (Phase 2 target)
    │
    ▼
  core_rpc_server (C++)  ◀─ on_* handlers (plain class; no epee HTTP base)
    │
    ▼
  cryptonote::core / p2p
```

`core_rpc_server` retains its `on_*` methods but no longer inherits
`epee::http_server_impl_base`. Axum is the sole HTTP acceptor. Epee KV
serialization remains inside `core_rpc_ffi.cpp` until Phase 2. Levin P2P
(`nodetool::node_server` / `epee::levin::`) remains C++ until a separate P2P
port — it is not part of this Phase 1 transport deletion.

## Files

| File | Role |
|------|------|
| `src/rpc/core_rpc_ffi.h` | C API header for the FFI facade |
| `src/rpc/core_rpc_ffi.cpp` | Dispatch tables mapping URIs/methods to `on_*` handlers |
| `rust/shekyl-daemon-rpc/` | Axum crate: server, routes, handlers, types |
| `rust/shekyl-daemon-rpc/src/ffi_exports.rs` | `shekyl_daemon_rpc_start/stop` FFI exports (daemon-only) |
| `src/shekyl/shekyl_ffi.h` | C++ declarations for Rust FFI functions |
| `src/daemon/daemon.cpp` | Daemon lifecycle: always starts Axum on the configured RPC port |
| `src/rpc/rpc_args.cpp` | Shared CLI; daemon registers bind/CORS only (`include_listener_tls_auth=false`) |

## Endpoint Coverage

- **JSON REST** endpoints (`/get_info`, `/get_transactions`, etc.)
  - Accept both **GET and POST** (matching historical epee behavior)
  - The legacy `/send_raw_transaction` + `/sendrawtransaction` pair was
    deleted (`design/DAEMON_SUBMIT_VERDICT.md` §9.3); transaction submit
    is the native `/submit_transaction` route below, not an FFI proxy
- **1 native Rust** endpoint: `POST /submit_transaction` — served
  directly by the Rust admission engine (`src/submit/`), never crossing
  the C++ dispatch tables (`design/DAEMON_SUBMIT_VERDICT.md` §2–§3)
- **Binary** endpoints (`/get_blocks.bin`, `/get_o_indexes.bin`, etc.)
  - POST-only; return **400 Bad Request** on parse failure
- **JSON-RPC 2.0** methods via `POST /json_rpc` (includes curve-tree and
  `get_archival_emission_claim_source`)

All URI aliases (e.g. `/getheight` ↔ `/get_height`) are registered on Axum.
Registration is FFI-table + Axum only — MAP macros are gone.

### Deleted decoy surface (no Axum route)

`get_output_distribution` / `/get_output_distribution.bin` (and
`wallet2::get_rct_distribution`) are deleted. FCMP++ does not use ring-decoy
distribution. **Rule-21 reopen:** iff a live wallet path re-acquires a
distribution consumer; re-evaluation shape: restore a typed Axum+FFI route
with a named caller, never “keep epee.”

## Restricted Mode

In restricted mode (`--restricted-rpc` or a separate restricted bind port):

- JSON REST: admin-only routes are not registered in the Axum router.
- JSON-RPC: admin-only methods are rejected with code `-32601` before C++.

Note: the restricted-method list exists in both Axum and (historically) epee
maps — dual-list single-sourcing is a FOLLOWUPS item.

## Auth, TLS, and remote access

| Context | Story |
|---------|--------|
| Local | Plaintext loopback (`127.0.0.1`). shekyld does **not** register `--rpc-login` or `--rpc-ssl*`. |
| Remote | Onion (address = key; `has_strong_verification` already) or a reverse proxy outside the daemon. |
| Wallet-RPC | Keeps full `--rpc-login` / `--rpc-ssl*` (separate process). |
| CLI outbound | `process_ssl` / `net_ssl` remain for `t_command_server` reaching a daemon. |

**Rule-21 reopen for in-daemon clearnet TLS / digest auth:** named production
need + threat-model review. Disposition is never “implement Axum `--rpc-ssl`”
as the remote-security story — that remains onion / reverse proxy.

## CORS

Default-deny (`CorsLayer::new()`). When `--rpc-access-control-origins` is set,
Axum honors the comma-separated allow-list (never `*`).

## Connection limits

`--rpc-max-connections` (total), `--rpc-max-connections-per-public-ip`, and
`--rpc-max-connections-per-private-ip` are **enforced by the Axum listener**.
The caps are parsed and cross-validated in `core_rpc_server::init` (C++) and
handed to the Rust listener via `shekyl_daemon_rpc_start`; enforcement itself is
a purpose-built Rust layer (`conn_limit`: `LimitedListener` + `ConnTracker`)
that admits each accepted TCP connection against the total and the applicable
per-IP cap (public vs. private/loopback), immediately closing any connection
over a cap and releasing the slot when a connection closes. `0` means unlimited
for a given dimension. The soft-limit arg remains advisory.

`get_info.rpc_connections_count` reports the live tracked total from that same
layer (both the REST and json_rpc surfaces; restricted RPC continues to
disclose `0`, matching the other peer/connection fields).

## PQC Readiness

- Default body limit: 10 MiB (configurable). With FCMP++ and per-input
  pqc_auths, a typical 2-in/2-out transaction is ~23 KB. The 10 MiB limit
  is sufficient for all realistic transaction sizes including multisig.
- No changes needed to the wire format; the FFI boundary passes raw JSON
  strings and binary blobs without interpretation.
- `get_outs` / `get_outs.bin` endpoints are removed — FCMP++ uses
  full-chain membership proofs, so there is no ring member fetching.
- Curve tree RPC endpoints — registered in the Axum/FFI JSON-RPC dispatch
  table (`src/rpc/core_rpc_ffi.cpp` `get_jsonrpc_table()`) since PR #174
  (2026-06-23):
  - `get_curve_tree_path` — Merkle path for a given leaf
  - `get_curve_tree_info` — current curve tree root hash, depth, leaf count
  - `get_curve_tree_checkpoint` — curve tree snapshot at a given height

## Running

```bash
shekyld                        # Axum on 11029
shekyld --testnet              # Axum on 12029
```

### Port Mapping

| Network  | P2P   | RPC (Axum) |
|----------|-------|------------|
| Mainnet  | 11021 | 11029      |
| Testnet  | 12021 | 12029      |
| Stagenet | 13021 | 13029      |

## Reachability predicate (Phase 1 audit)

A method is **live** iff it has an Axum route (or `/json_rpc` → FFI method)
**and** a live consumer. MAP macros are gone; registration is FFI-only + Axum.

| Surface | Axum | FFI | Live consumer | Disposition |
|---------|------|-----|---------------|-------------|
| JSON REST (info, height, txs, pool, …) | yes | yes | wallets / CLI | keep |
| Binary sync (`/get_blocks.bin`, hashes, indexes) | yes | yes | wallet refresh | keep |
| JSON-RPC admin + query set | `/json_rpc` | yes | wallets / tools | keep |
| `POST /submit_transaction` | native Rust | n/a | wallets | keep |
| `get_archival_emission_claim_source` | `/json_rpc` | yes | claim-builder | keep |
| `get_output_distribution` (+ `.bin`) | **no** | **removed** | none (`get_rct_distribution` deleted) | deleted |
| epee HTTP listener / `--no-rust-rpc` | n/a | n/a | none | deleted |

## Phase 2 (KV serialization)

Replace epee portable-storage in `core_rpc_ffi.cpp` with a Rust-native
codec. Out of scope for the Phase 1 transport deletion.

## Thread Safety

C++ `on_*` handlers are designed for concurrent access. Axum dispatches each
request on a Tokio worker; FFI calls use `spawn_blocking`. `CoreRpc` is
`Send + Sync`.
