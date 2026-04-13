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
    ├── lib.rs               # Library entry point, re-exports
    ├── main.rs              # Standalone binary (clap CLI)
    ├── ffi.rs               # Raw C FFI bindings to wallet2_ffi.h
    ├── wallet.rs            # Safe Wallet2 wrapper
    ├── handlers.rs          # RPC dispatch (routes to wallet.json_rpc_call)
    ├── server.rs            # axum HTTP server + JSON-RPC routing
    ├── types.rs             # Request/response serde types
    ├── multisig_handlers.rs # FROST multisig RPC (feature = "multisig")
    └── scanner_state.rs     # Rust scanner state (feature = "rust-scanner")
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
  libboost-all-dev libssl-dev libunbound-dev \
  libsodium-dev libhidapi-dev libusb-1.0-0-dev \
  libprotobuf-dev protobuf-compiler libudev-dev
```

**macOS** (Homebrew):
```bash
brew install cmake boost hidapi openssl libpgm \
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

89 RPC methods from `wallet_rpc_server.h` are implemented in the
`wallet2_ffi_json_rpc` dispatcher (9 classical multisig methods were removed;
FROST multisig is handled by native Rust handlers, see below):

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
| FROST Multisig (`multisig` feature) | `multisig_register_group`, `multisig_list_groups`, `multisig_create_signing`, `multisig_sign_preprocess`, `multisig_sign_add_preprocess`, `multisig_sign_nonce_sums`, `multisig_sign_own`, `multisig_sign_add_shares`, `multisig_sign_aggregate` |
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
  ├── multisig_* methods → multisig_handlers (native Rust, "multisig" feature)
  │     MultisigState, MultisigSigningSession, MultisigGroup
  │
  └── remaining methods → C++ FFI (unchanged)
        transfer, sweep_*, sign_transfer, ...
```

### Key Types

| Module | Type | Purpose |
|--------|------|---------|
| `shekyl-scanner` | `Scanner` | Hybrid PQC KEM block/tx/output scan pipeline |
| `shekyl-scanner` | `RecoveredWalletOutput` | Scan result with all KEM-derived secrets + key image |
| `shekyl-scanner` | `TransferDetails` | Extended output with staking + PQC fields + `eligible_height` |
| `shekyl-scanner` | `WalletState` | In-memory transfer tracking, key image dedup, spend detection |
| `shekyl-scanner` | `BalanceSummary` | Staking-aware balance breakdown (uses `eligible_height`) |
| `shekyl-scanner::sync` | `run_sync_loop` | Background daemon polling + scan + spend detection loop |
| `shekyl-scanner::sync` | `SyncProgress` | Per-block progress event (height, outputs found, spends) |
| `shekyl-wallet-rpc` | `ScannerState` | Thread-safe wrapper around `WalletState` |

### GUI Integration

The Tauri GUI wallet's `wallet_bridge.rs` now includes a `ScannerState`
alongside the `Wallet2` handle. Query methods (`get_scanner_balance`,
`get_scanner_staked_outputs`, `get_scanner_height`) read from the Rust scanner
state. Mutation methods continue to use the C++ FFI.

## FROST Multisig RPC (`multisig` feature)

When compiled with `--features multisig`, the RPC server provides native Rust
FROST multisig endpoints. These bypass the C++ FFI entirely and are routed
directly to `multisig_handlers.rs` in the `json_rpc_handler`.

Multisig state (`MultisigState`) is held in `AppState` under its own `Mutex`,
separate from the `wallet` lock. This allows multisig operations to proceed
without blocking wallet queries.

**DKG is not exposed over RPC.** The `dkg-pedpop` crate's round message types
do not implement `serde::Serialize`/`Deserialize`, making direct RPC transport
impractical. DKG is handled through the `shekyl-wallet-core` API with
file-based message exchange (air-gap compatible). See `docs/PQC_MULTISIG.md`
for the DKG ceremony flow.

**Signing RPC methods:**

| Method | Purpose |
|--------|---------|
| `multisig_register_group` | Register a `MultisigGroup` (threshold keys + PQC material) |
| `multisig_list_groups` | List registered group IDs |
| `multisig_create_signing` | Create a `MultisigSigningSession` for a set of inputs |
| `multisig_sign_preprocess` | Generate FROST commitments for the local participant |
| `multisig_sign_add_preprocess` | Add a remote participant's commitments |
| `multisig_sign_nonce_sums` | Retrieve aggregated nonce sums (hex bytes) |
| `multisig_sign_own` | Produce signing shares for the local participant |
| `multisig_sign_add_shares` | Add a remote participant's signing shares |
| `multisig_sign_aggregate` | Aggregate all shares and produce the FCMP++ proof |

All byte fields are hex-encoded in request/response JSON.

## Sync Loop

The `shekyl-scanner::sync` module (feature-gated behind `rust-scanner`)
implements the background sync loop:

```rust
pub async fn run_sync_loop<R, P, F>(
    rpc: R,                            // Rpc trait implementor
    scanner: Arc<Mutex<Scanner>>,      // Hybrid PQC KEM scanner
    state: Arc<Mutex<WalletState>>,    // In-memory wallet state
    cancel: CancellationToken,         // Graceful shutdown signal
    poll_interval: Duration,           // Sleep between tip polls
    flush_every_block: bool,           // Mobile: true; Desktop: false
    on_progress: P,                    // SyncProgress callback
    on_flush: F,                       // Persistence callback
) -> Result<(), SyncError>
```

The loop fetches blocks from `wallet_state.height() + 1` up to the daemon
tip via `get_scannable_block_by_number`, scans each block for wallet outputs,
extracts key images from all block transactions for spend detection, and
emits a `SyncProgress` event per block.

**Reorg detection:** Before processing each block, the loop compares
the block's `header.previous` hash against the hash stored in `WalletState`
for the prior height. On mismatch, it walks backwards (via `find_fork_point`)
to locate the common ancestor, calls `WalletState::handle_reorg` to roll
back affected transfers, flushes, and restarts scanning from the fork point.

**Block fetch retries:** Individual `get_scannable_block_by_number` calls
retry up to 5 times with exponential backoff (500ms initial, 30s cap)
before aborting. `get_height` retries indefinitely on each poll cycle.

**Flush strategy:**
- Desktop: flush every 100 blocks plus at the tip.
- Mobile: flush every block (OS can kill without warning).
- Always flushes on reorg rollback and on cancellation before returning.

**Cancellation:** Dropping the `CancellationToken` or calling `.cancel()`
causes the loop to finish the current block and return cleanly.

## Future Work

- **FCMP++ signing in Rust**: Transaction construction (FCMP++ proofs, PQC
  key signing) is the remaining major C++ dependency. Once implemented, the
  FFI layer can be removed entirely.
- **DKG RPC transport**: If `dkg-pedpop` gains `serde` support (or a custom
  serialization layer is written), DKG round messages could be exposed over
  RPC for non-airgapped workflows.
- **GUI multisig integration**: Wire the FROST multisig RPC endpoints into the
  Tauri wallet's `wallet_bridge.rs` for GUI-driven multisig signing.
- **Remove C++ `wallet_rpc_server`**: Once the Rust RPC is proven in production,
  the C++ `wallet_rpc_server.cpp` and its epee HTTP infrastructure can be removed.
