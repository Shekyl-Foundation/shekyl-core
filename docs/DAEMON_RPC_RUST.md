# Daemon RPC: Rust/Axum Migration

Phase 1 of the epee-to-Rust migration replaces the daemon's HTTP transport layer
with Axum while keeping all handler logic in C++.

## Architecture

```
  Client
    │
    ▼
  Axum (Rust)            ◀─ HTTP transport, CORS, body limits, route dispatch
    │
    ▼
  CoreRpc (Rust)         ◀─ FFI wrapper, spawn_blocking for C++ calls
    │
    ▼ C ABI
  core_rpc_ffi.cpp       ◀─ Dispatch tables: URI → handler, epee serialization
    │
    ▼
  core_rpc_server (C++)  ◀─ on_* handlers (unchanged)
    │
    ▼
  cryptonote::core / p2p
```

The `core_rpc_server` class retains its `on_*` methods and still inherits from
`epee::http_server_impl_base` (the legacy server remains available via
`--no-rust-rpc`). The Axum server runs on a dedicated Tokio runtime started
from the Rust FFI.

## Files

| File | Role |
|------|------|
| `src/rpc/core_rpc_ffi.h` | C API header for the FFI facade |
| `src/rpc/core_rpc_ffi.cpp` | Dispatch tables mapping URIs/methods to `on_*` handlers |
| `rust/shekyl-daemon-rpc/` | Axum crate: server, routes, handlers, types; produces `libshekyl_daemon_rpc.a` |
| `rust/shekyl-daemon-rpc/src/ffi_exports.rs` | `shekyl_daemon_rpc_start/stop` FFI exports (daemon-only) |
| `src/shekyl/shekyl_ffi.h` | C++ declarations for Rust FFI functions |
| `src/daemon/daemon.cpp` | Daemon lifecycle: start/stop Rust RPC alongside epee |
| `tests/rpc_comparison/compare_rpc.sh` | Validation harness for dual-server diffing |

## Endpoint Coverage

- **33 JSON REST** endpoints (`/get_info`, `/send_raw_transaction`, etc.)
  - Accept both **GET and POST** (matching epee behavior)
- **8 binary** endpoints (`/get_blocks.bin`, `/get_o_indexes.bin`, etc.)
  - POST-only; return **400 Bad Request** on parse failure (matching epee)
- **48 JSON-RPC 2.0** methods (`get_block_count`, `get_block_template`, etc.)
  - POST-only (per JSON-RPC 2.0 spec)
- **90 total** dispatcher registrations (74 unique handlers)

All URI aliases (e.g. `/getheight` ↔ `/get_height`) are registered.

## Restricted Mode

In restricted mode (`--restricted-rpc`):

- JSON REST: admin-only routes (`/start_mining`, `/stop_daemon`, etc.) are not
  registered in the Axum router.
- JSON-RPC: admin-only methods are rejected with code `-32601` before reaching
  the C++ handler.

## PQC Readiness

- Default body limit: 10 MiB (configurable). With FCMP++ and per-input
  pqc_auths, a typical 2-in/2-out transaction is ~23 KB. The 10 MiB limit
  is sufficient for all realistic transaction sizes including multisig.
- No changes needed to the wire format; the FFI boundary passes raw JSON
  strings and binary blobs without interpretation.
- `get_outs` / `get_outs.bin` endpoints are removed — FCMP++ uses
  full-chain membership proofs, so there is no ring member fetching.
- Curve tree RPC endpoints are implemented:
  - `get_curve_tree_path` — retrieve a Merkle path for a given leaf
  - `get_curve_tree_info` — retrieve the current curve tree root hash, depth, and leaf count
  - `get_curve_tree_checkpoint` — retrieve a curve tree snapshot at a given height

## Running

```bash
# Rust RPC is enabled by default on port = epee_port + 10000
shekyld --testnet              # epee 12029, Axum 22029
shekyld                        # epee 11029, Axum 21029

# Disable Rust RPC (legacy only)
shekyld --no-rust-rpc

# Validation: run both servers and diff responses
./tests/rpc_comparison/compare_rpc.sh 12029 22029
```

### Port Mapping

| Network  | P2P   | epee RPC | Axum RPC |
|----------|-------|----------|----------|
| Mainnet  | 11021 | 11029    | 21029    |
| Testnet  | 12021 | 12029    | 22029    |
| Stagenet | 13021 | 13029    | 23029    |

## Validation Results

Tested on testnet (2026-04-02) with dual-server mode. Test data saved to
`shekyl-dev/data/rpc_comparison/`.

- **23 PASS** across JSON REST, JSON-RPC, and restricted endpoints
- **2 expected diffs** (`get_info` via both REST and JSON-RPC): `rpc_connections_count`
  differs because epee counts its own active HTTP connection while Axum does not
  go through epee's connection tracker
- **2 binary SKIP**: Both servers return 400 for empty-POST binary requests
  (matching behavior confirmed); full binary validation requires wallet sync test

### Cutover Remaining Work

Before removing the epee HTTP listener entirely:

1. **Wallet sync test** -- connect `shekyl-cli` to Axum-only RPC,
   verify block sync via `/getblocks.bin` and curve tree path fetch via `/get_curve_tree_path`
2. **Standard port binding** -- when Axum is sole server, bind to 11029/12029/13029
   (not +10000) so existing clients and config files work unchanged

## Thread Safety

The C++ `core_rpc_server` handlers are designed for concurrent access (epee's
thread pool model). Axum dispatches each request on a Tokio worker, and the FFI
call is offloaded via `tokio::task::spawn_blocking` to avoid blocking the async
runtime. The `CoreRpc` wrapper is `Send + Sync`.

## Future Work (Phases 2–4)

- **Phase 2**: Replace epee KV serialization with a Rust encoding crate.
- **Phase 3**: Replace P2P networking (`abstract_tcp_server2`, Levin) with Rust.
- **Phase 4**: Remove `contrib/epee/` entirely; strip remaining Boost deps.
