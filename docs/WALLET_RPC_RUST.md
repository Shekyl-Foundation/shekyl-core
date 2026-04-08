# Rust Wallet RPC Design Document

## Overview

The Rust wallet RPC layer replaces the C++ `wallet_rpc_server` with a Rust
implementation that calls the existing C++ `wallet2` library through a C FFI
facade. This provides:

- **Standalone binary**: `shekyl-wallet-rpc`, a drop-in replacement for the
  legacy C++ wallet RPC server
- **Embedded library**: Linked directly into the Tauri GUI wallet for
  zero-overhead wallet operations without HTTP or process spawning

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     GUI Wallet (Tauri)                       │
│  ┌───────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ wallet_bridge  │  │  commands    │  │  daemon_rpc      │ │
│  │ (direct FFI)   │  │  (Tauri cmds)│  │  (HTTP to daemon)│ │
│  └───────┬───────┘  └──────────────┘  └──────────────────┘ │
└──────────┼──────────────────────────────────────────────────┘
           │ (in-process Rust call)
┌──────────▼──────────────────────────────────────────────────┐
│              shekyl-wallet-rpc (Rust crate)                  │
│  ┌─────────┐  ┌──────────┐  ┌───────┐  ┌───────────────┐  │
│  │ wallet.rs│  │handlers.rs│  │server │  │ types.rs      │  │
│  │(Wallet2) │  │(dispatch) │  │(axum) │  │(serde structs)│  │
│  └────┬─────┘  └──────────┘  └───────┘  └───────────────┘  │
└───────┼─────────────────────────────────────────────────────┘
        │ (C FFI via ffi.rs)
┌───────▼─────────────────────────────────────────────────────┐
│              wallet2_ffi.cpp / wallet2_ffi.h                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ wallet2_ffi_json_rpc() — generic JSON-RPC dispatcher │   │
│  │ + dedicated functions for lifecycle, transfer, etc.  │   │
│  └──────────────────────┬───────────────────────────────┘   │
└─────────────────────────┼───────────────────────────────────┘
                          │ (C++ method calls)
┌─────────────────────────▼───────────────────────────────────┐
│                    wallet2 (C++ core)                         │
│  Crypto · Sync · TX construction · Key management · LMDB    │
└──────────────────────────────────────────────────────────────┘
```

## FFI Boundary Design

### JSON at the boundary

Complex types cross the FFI as JSON strings serialized by RapidJSON on the C++
side and deserialized by serde on the Rust side. This avoids maintaining dozens
of `repr(C)` structs and keeps the facade thin.

Simple scalar returns (height, bool, version) use direct C types.

### Opaque handle

```c
typedef struct wallet2_handle wallet2_handle;

wallet2_handle* wallet2_ffi_create(uint8_t nettype);
void wallet2_ffi_destroy(wallet2_handle* w);
```

The `wallet2_handle` wraps a `tools::wallet2` instance plus last-error state.
Rust wraps it in `Wallet2` with a `Drop` impl that calls `destroy`.

### Generic dispatcher

```c
char* wallet2_ffi_json_rpc(wallet2_handle* w, const char* method, const char* params_json);
```

Routes any RPC method name to the corresponding wallet2 call. Returns a
heap-allocated JSON string (caller frees with `wallet2_ffi_free_string`).
On error, returns `NULL` and sets the handle's last-error fields.

### Thread safety

`wallet2` is not thread-safe. The Rust `Wallet2` wrapper is `Send` but not
`Sync`. Thread safety is enforced by wrapping it in `std::sync::Mutex` in the
application state (both the axum server's `AppState` and the Tauri `AppState`).

## Crate Structure

```
rust/shekyl-wallet-rpc/
├── Cargo.toml
└── src/
    ├── lib.rs        # Library entry point, re-exports
    ├── main.rs       # Standalone binary (clap CLI)
    ├── ffi.rs        # Raw C FFI bindings to wallet2_ffi.h
    ├── wallet.rs     # Safe Wallet2 wrapper
    ├── handlers.rs   # RPC dispatch (routes to wallet.json_rpc_call)
    ├── server.rs     # axum HTTP server + JSON-RPC routing
    └── types.rs      # Request/response serde types
```

## GUI Wallet Integration

The GUI wallet (`shekyl-gui-wallet`) depends on `shekyl-wallet-rpc` as a Rust
library. The integration layer is in `wallet_bridge.rs`:

- **`WalletHandle`**: `Mutex<Option<Wallet2>>` — lazily initialized
- **`init()`**: Creates a `Wallet2` instance, connects to daemon
- **`shutdown()`**: Drops the `Wallet2` instance
- **Per-method functions**: `create_wallet()`, `get_balance()`, `transfer()`,
  etc. — each acquires the mutex, calls the `Wallet2` method, deserializes
  the JSON result into typed Rust structs

### Build requirements

The GUI wallet's `build.rs` links against pre-built Shekyl C++ libraries.

#### Recommended: Using `contrib/depends` (CI builds, static linking)

This builds all third-party libraries (Boost, OpenSSL, etc.) from source
with static linking. Produces a portable binary with no distro-versioned
runtime dependencies.

```bash
# 1. Clone shekyl-core
git clone --recurse-submodules https://github.com/Shekyl-Foundation/shekyl-core.git ../Shekyl

# 2. Build everything via depends (downloads + builds all deps from source)
cd ../Shekyl && make depends target=x86_64-unknown-linux-gnu -j$(nproc)

# 3. Build the GUI wallet
cd shekyl-gui-wallet
export SHEKYL_BUILD_DIR=$(pwd)/../Shekyl/build/x86_64-unknown-linux-gnu/release
export SHEKYL_DEPENDS_PREFIX=$(pwd)/../Shekyl/contrib/depends/x86_64-unknown-linux-gnu
npx tauri build
```

#### Quick local development (dynamic linking)

For faster iteration when you already have system libraries installed:

```bash
# 1. Build shekyl-core with system libraries
cmake -S ../Shekyl -B ../Shekyl/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTS=OFF
cmake --build ../Shekyl/build -- -j$(nproc)

# 2. Build the GUI wallet (dynamic linking, no SHEKYL_DEPENDS_PREFIX)
export SHEKYL_BUILD_DIR=$(pwd)/../Shekyl/build
cd shekyl-gui-wallet/src-tauri
cargo build
```

#### Platform-specific dependencies (local dev only)

**Linux (Ubuntu/Debian)**:
```bash
sudo apt-get install -y \
  build-essential cmake pkg-config \
  libboost-all-dev libssl-dev libzmq3-dev libunbound-dev \
  libsodium-dev libhidapi-dev libusb-1.0-0-dev \
  libprotobuf-dev protobuf-compiler libudev-dev
```

**macOS** (Homebrew):
```bash
brew install cmake boost hidapi openssl zmq libpgm \
  miniupnpc expat protobuf abseil libsodium unbound
```

**Windows**: Not yet supported. The C++ codebase builds with MinGW but the
Tauri toolchain requires MSVC-compatible `.lib` files. An MSVC compatibility
investigation is in progress.

#### How `build.rs` works

The build script links 21 static libraries from the shekyl-core build tree
plus the `shekyl_ffi` Rust FFI crate. It automatically derives the source
directory (for the Rust FFI library) from `SHEKYL_BUILD_DIR`'s parent. To
override, set `SHEKYL_SOURCE_DIR` explicitly.

When `SHEKYL_DEPENDS_PREFIX` is set (pointing at the `contrib/depends`
output), all third-party libraries (Boost, OpenSSL, sodium, etc.) are
statically linked from that prefix. When unset, they are dynamically linked
from system paths (suitable for local development).

If `SHEKYL_BUILD_DIR` is not set, the build succeeds but FFI functions are
not linked — the wallet bridge will be available at the type level but calls
will fail at link time. This allows CI lint/check passes without a full C++
build.

### What was removed

| File | Purpose | Replacement |
|------|---------|-------------|
| `wallet_process.rs` | Spawn/manage `shekyl-wallet-rpc` child process | Direct FFI via `wallet_bridge.rs` |
| `wallet_rpc.rs` | HTTP JSON-RPC client to wallet-rpc process | Direct FFI via `wallet_bridge.rs` |

## RPC Method Coverage

All 98 RPC methods from `wallet_rpc_server.h` are implemented in the
`wallet2_ffi_json_rpc` dispatcher:

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
| Multisig | `is_multisig`, `prepare_multisig`, `make_multisig`, `finalize_multisig`, `exchange_multisig_keys`, `export_multisig_info`, `import_multisig_info`, `sign_multisig`, `submit_multisig` |
| Background sync | `setup_background_sync`, `start_background_sync`, `stop_background_sync` |
| Staking | `stake`, `unstake`, `get_staked_outputs`, `get_staked_balance`, `claim_rewards` |
| Fees | `estimate_tx_size_and_weight`, `get_default_fee_priority` |
| Meta | `get_version`, `get_languages` |

## Scanner Integration (`rust-scanner` feature)

When `shekyl-wallet-rpc` is compiled with `--features rust-scanner`, the RPC
server uses split routing:

- **Scanner-backed methods** are handled natively in Rust via `shekyl-scanner`:
  `get_balance`, `get_transfers`, `incoming_transfers`, `get_transfer_by_txid`,
  `get_payments`, `get_bulk_payments`, `get_height`, `get_staked_outputs`,
  `get_staked_balance`
- **All other methods** continue routing through the C++ FFI

### Architecture with Scanner

```
HTTP POST /json_rpc → handlers::dispatch_with_scanner(method)
  │
  ├── scanner-backed methods → shekyl-scanner (native Rust)
  │     WalletState, BalanceSummary, TransferDetails
  │
  └── remaining methods → C++ FFI (unchanged)
        transfer, sweep_*, sign_transfer, multisig, ...
```

### Key Types

| Module | Type | Purpose |
|--------|------|---------|
| `shekyl-scanner` | `Scanner` | Block/tx/output scan pipeline |
| `shekyl-scanner` | `TransferDetails` | Extended output with staking + PQC fields |
| `shekyl-scanner` | `WalletState` | In-memory transfer tracking, key image dedup |
| `shekyl-scanner` | `BalanceSummary` | Staking-aware balance breakdown |
| `shekyl-wallet-rpc` | `ScannerState` | Thread-safe wrapper around `WalletState` |

### GUI Integration

The Tauri GUI wallet's `wallet_bridge.rs` now includes a `ScannerState`
alongside the `Wallet2` handle. Query methods (`get_scanner_balance`,
`get_scanner_staked_outputs`, `get_scanner_height`) read from the Rust scanner
state. Mutation methods continue to use the C++ FFI.

## Future Work

- **Scanner sync loop**: Implement the background refresh loop that drives the
  Rust scanner (fetch blocks via daemon RPC, feed to `Scanner::scan`, update
  `WalletState`). Currently the scanner state must be populated externally.
- **FCMP++ signing in Rust**: Transaction construction (FCMP++ proofs, PQC
  key signing) is the remaining major C++ dependency. Once implemented, the
  FFI layer can be removed entirely.
- **PQC multisig migration**: The multisig dispatch functions use the current
  wallet2 API. When the PQC multisig redesign (see `docs/PQC_MULTISIG.md`) is
  implemented, these dispatchers will need updating to match the new API.
- **Remove C++ `wallet_rpc_server`**: Once the Rust RPC is proven in production,
  the C++ `wallet_rpc_server.cpp` and its epee HTTP infrastructure can be removed.
