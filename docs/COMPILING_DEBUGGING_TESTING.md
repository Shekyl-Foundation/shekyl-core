# Compiling, debugging and testing efficiently

This document describes ways of compiling, debugging and testing efficiently for various use cases.
The intended audience are developers, who want to leverage build and test tricks in Shekyl via `CMake`. The document will lower the entry point for these developers.
Before reading this document, please consult section "Build instructions" in the main README.md.
Some information from README.md will be repeated here, but the aim is to go beyond it.

PQC and FCMP++ note:

- Shekyl's rebooted chain design depends on Rust-based PQC and FCMP++ components
- Rust should be treated as required for consensus-valid builds
- The FCMP++ Rust crates (`shekyl-fcmp`, `shekyl-address`) are required for
  consensus-valid builds alongside the existing `shekyl-crypto-pq` and
  `shekyl-ffi` crates
- The canonical PQC format/spec is documented in
  `docs/POST_QUANTUM_CRYPTOGRAPHY.md`

## Rust Reproducible Builds

Shekyl includes three Rust crates in the consensus-critical build path: `shekyl-crypto-pq`, `shekyl-fcmp`, and `shekyl-ffi`. Reproducibility of the Rust static library is essential for release verification.

### Requirements

- **x86_64 host only.** Rust does not produce bit-identical output across CPU architectures (see Monero #9801). Release artifacts must be built on x86_64 Linux. ARM64, RISC-V, and other architectures may produce functionally correct binaries but they will not match the deterministic reference hash.
- **Pinned toolchain.** The workspace uses `Cargo.lock` to pin all dependency versions, including git dependencies (monero-oxide fork at commit `92af05e0`). All `cargo build` invocations in CI and CMake pass `--locked` to enforce this.
- **Stable Rust.** The workspace targets stable Rust (currently 1.94.0+). Nightly features are not used.

### Verifying determinism locally

```bash
cd rust
cargo build --locked --release -p shekyl-ffi
sha256sum target/release/libshekyl_ffi.a
cargo clean -p shekyl-ffi --release
cargo build --locked --release -p shekyl-ffi
sha256sum target/release/libshekyl_ffi.a
# Both hashes must match
```

### Guix integration

Guix gained improved Rust packaging support in 2025 with Cargo.lock lockfile importing. The `guix-rustup` third-party channel provides access to pinned stable Rust toolchains. Full Guix reproducible release integration is tracked as a Phase 1a.2 deliverable. Until Guix integration is validated, release builds use the CI determinism check (build twice, diff hashes) as the reproducibility gate.

## Basic compilation

Shekyl can be compiled via the main `Makefile`, using one of several targets listed there.
The targets are actually presets for `CMake` calls with various options, plus `make` commands for building or in some cases `make test` for testing.
It is possible to extract these `CMake` calls and modify them for your specific needs. For example, a minimal external cmake command to compile Shekyl, executed from within a newly created build directory could look like:

`cmake -S "$DIR_SRC" -DCMAKE_BUILD_TYPE=Release && make`

where the variable `DIR_SRC` is expected to store the path to the Shekyl source code.

## Use cases

### Test Driven Development (TDD) - shared libraries for release builds

Building shared libraries spares a lot of disk space and linkage time. By default only the debug builds produce shared libraries. If you'd like to produce dynamic libraries for the release build for the same reasons as it's being done for the debug version, then you need to add the `BUILD_SHARED_LIBS=ON` flag to the `CMake` call, like the following:

`cmake -S "$DIR_SRC" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON && make`

A perfect use case for the above call is following the Test Driven Development (TDD) principles. In a nutshell, you'd first write a couple of tests, which describe the (new) requirements of the class/method that you're about to write or modify. The tests will typically compile for quite a long time, so ideally write them once. After you're done with the tests, the only thing left to do is to keep modifying the implementation for as long as the tests are failing. If the implementation is contained properly within a .cpp file, then the only time cost to be paid will be compiling the single source file and generating the implementation's shared library. The test itself will not have to be touched and will pick up the new version of the implementation (via the shared library) upon the next execution of the test.

### Project generation for IDEs

CMake allows to generate project files for many IDEs. The list of supported project files can be obtained by writing in the console:

`cmake -G`

For instance, in order to generate Makefiles and project files for the Code::Blocks IDE, this part of the call would look like the following:

`cmake -G "CodeBlocks - Unix Makefiles" (...)`

The additional artifact of the above call is the `shekyl.cbp` Code::Blocks project file in the build directory.

### Debugging in Code::Blocks (CB)

First prepare the build directory for debugging using the following example command, assuming, that the path to the source dir is being held in the DIR_SRC variable, and using 2 cores:

`cmake -S "$DIR_SRC" -G "CodeBlocks - Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON && make -j 2`

After a successful build, open the `shekyl.cbp` with CB. From the CB's menu bar select the target, that you want debug. Assuming these are unit tests:

`Build -> Select target -> Select target -> unit_tests`

In order to lower the turnaround times, we will run a specific portion of code of interest, without having to go through all the time costly initialization and execution of unrelated parts. For this we'll use GTest's capabilities of test filtering. From the build directory run the following command to learn all the registered tests:

`tests/unit_tests/unit_tests --gtest_list_tests`

For example, if you're only interested in logging, you'd find in the list the label `logging.` and its subtests. To execute all the logging tests, you'd write in the console:

`tests/unit_tests/unit_tests --gtest_filter="logging.*"`

This parameter is what we need to transfer to CB, in order to reflect the same behaviour in the CB's debugger. From the main menu select:

`Project -> Set program's arguments...`

Then in the `Program's arguments` textbox you'd write in this case:

`--gtest_filter="logging.*"`

Verify if the expected UTs are being properly executed with `F9` or select:

`Build -> Build and run`

If everything looks fine, then after setting some breakpoints of your choice, the target is ready for debugging in CB via:

`Debug -> Start/Continue`

## Windows (MSVC) wallet-core build

The project supports building wallet-core libraries with MSVC on Windows.
This is primarily used for the GUI wallet (Tauri/Rust) which links the C++
static libraries.

### Prerequisites

- **Visual Studio 2022 (17.x)** or **Visual Studio 2026 (18.x)** with the
  C++ Desktop workload.  The CI uses VS 2026 for forward compatibility,
  but the build works on VS 2022 as well thanks to the
  `CryptonightR_JIT_stub.c` workaround for the PDB ICE (see below).
- vcpkg (for Boost, libsodium, OpenSSL, ZeroMQ, libunbound, LMDB)
- Rust toolchain (`stable-x86_64-pc-windows-msvc`)
- CMake 3.25+ (or CMake 4.0+ if using VS 2026)

### Build command

```powershell
cmake -S . -B build\msvc-release -G "Visual Studio 18 2026" -A x64 ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-windows-static ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DUSE_DEVICE_TREZOR=OFF
cmake --build build\msvc-release --config Release --parallel
```

### Known MSVC Internal Compiler Error (ICE) history

MSVC has two known ICE triggers in this codebase.  Both have been
worked around.  The diagnosis is recorded here for future reference.

#### ICE 1: Empty checkpoint array initializers (`obj_blocks`)

**Symptom:** `CL.exe exited with code -529706956` on `obj_blocks.vcxproj`.

**Root cause:** The files `src/blocks/*.dat` are 0 bytes before genesis
data is populated. The CMake generator (`blocks_generator.cmake`) produced
`const unsigned char name[]={};` -- an empty array initializer that is
valid C99/C11 but triggers an MSVC 14.44 parser crash.

**Fix (permanent):** Modified `blocks_generator.cmake` to emit a 1-byte
placeholder (`{0x00}`) with a separate `_len = 0` sentinel for empty
`.dat` files.  This is correct on all compilers, not just a workaround:

```c
const unsigned char checkpoints[]={ 0x00 };
const size_t checkpoints_len = 0;
```

Consumers check `_len` rather than `sizeof()` to detect empty data.

#### ICE 2: PDB type server crash (`obj_cncrypto`)

**Symptom:** All individual `.c`/`.cpp` files in `src/crypto/` compile
successfully, then the compiler crashes during the `Generating Code...`
phase with:

```text
INTERNAL COMPILER ERROR in 'CL.exe'
CL!CloseTypeServerPDB()+0x16ef23
CL!CloseTypeServerPDB()+0x1b7502
```

**Diagnosis sequence** (tested on MSVC 14.44 and 14.50):

| Attempt | Flag / Change | Result |
| --- | --- | --- |
| Limit parallelism | `/MP1 /FS` | Still crashed |
| Reduce optimization | `/MP1 /O1` | Still crashed |
| Disable optimization | `/MP1 /Od` | Still crashed -- ruled out optimizer |
| Disable SSA optimizer | `/MP1 /d2SSAOptimizer-` | Still crashed, stack trace revealed `CloseTypeServerPDB` |
| Embed debug info | `/MP1 /Z7` | Still crashed -- PDB type server invoked even with `/Z7` |
| Split OBJECT library | 5 targets | Reduced blast radius but `obj_cncrypto_rx` still crashed |
| Guard `CryptonightR_template.h` | exclude from MSVC | Reduced dead symbols; ICE persisted |
| Upgrade to MSVC 14.50 (VS 2026) | | Still crashed -- same `CloseTypeServerPDB` stack |
| **Replace `CryptonightR_JIT.c` with stub** | | **Resolved** |

The crash is in MSVC's shared PDB (Program Database) type server.  It
reproduces on both MSVC 14.44 (VS 2022) and 14.50 (VS 2026).  The root
cause is `CryptonightR_JIT.c` -- on MSVC, the function body is dead code
(the entire JIT path is `#ifdef __i386 || __x86_64__`), but its
heavyweight includes (`variant4_random_math.h` with 70 unrolled switch
cases, `CryptonightR_template.h` with 514 assembly symbol declarations)
overwhelm the PDB type server during the "Generating Code..." phase.

**Fix:** `src/crypto/CryptonightR_JIT_stub.c` provides the same
`v4_generate_JIT_code() { return -1; }` stub without the problematic
includes.  On MSVC, the CMake build uses the stub; on GCC/Clang, the
full implementation with assembly template is used as before.

**Additional hardening kept in the codebase** (harmless, good hygiene):

- `src/crypto/CMakeLists.txt` splits `cncrypto` into six OBJECT library
  groups (`hash`, `ops`, `slowhash`, `rx`, `jit`, `cpp`).  This reduces
  per-target TU count and is harmless on all compilers.
- `src/crypto/CryptonightR_JIT.c` guards `#include "CryptonightR_template.h"`
  behind `__i386 || __x86_64__` (GCC/Clang only) since the 514 assembly
  symbol declarations it contains are dead on MSVC.
- `src/crypto/c_threads.h` includes `<process.h>` on Windows for correct
  `_beginthreadex` prototype (prevents handle truncation on 64-bit).
- `src/crypto/slow-hash.c` extends the `force_software_aes()` guard to
  include `_M_X64`.

---

## Upstream Monero PRs — triage (April 2026)

### Applied

| PR | Status | Notes |
| --- | --- | --- |
| [#6937](https://github.com/monero-project/monero/pull/6937) | Already present | `monero_set_target_no_relink` + `RELINK_TARGETS` option in root `CMakeLists.txt` |
| [#9762](https://github.com/monero-project/monero/pull/9762) | Already present | `test_p2p_tx_propagation()` uses deadline-based polling with Dandelion++ timeout |
| [#9795](https://github.com/monero-project/monero/pull/9795) | Applied | `test_p2p_reorg()` rewritten to deadline-based polling (was fixed `sleep(10)` loops) |
| [#9858](https://github.com/monero-project/monero/pull/9858) | Applied | Extra warnings (`-Wsuggest-override`, `-Wthread-safety`, etc.) and ARM64 branch protection |
| [#9898](https://github.com/monero-project/monero/pull/9898) | Technique adopted | PR was closed upstream; adopted the author's recommended approach: `-ffunction-sections -fdata-sections` + linker dead-code stripping |

### Track for future work

| PR | Area | Why it matters for Shekyl |
| --- | --- | --- |
| [#10157](https://github.com/monero-project/monero/pull/10157) | Perf | Cache mempool input verification results. PQC hybrid verification (ML-DSA-65) is more expensive than classical Ed25519, making the caching benefit proportionally larger. Depends on #10156 and #10172; needs PQC-aware verification IDs. See `STRUCTURAL_TODO.md` re: `txpool_tx_meta_t` padding layout. |
| [#10084](https://github.com/monero-project/monero/pull/10084) | Arch | `wallet2_basic` library extraction. Shekyl already has `wallet2_ffi.cpp` on a parallel modularization path. Use the upstream type list as a roadmap for wallet Rust migration. |
| [#9801](https://github.com/monero-project/monero/pull/9801) | Repro | Rust in Guix reproducible builds. Shekyl uses Gitian and lacks `contrib/guix/`. Key constraint: Rust cross-arch builds are NOT bit-identical (x86_64 hosts required). Track for when Rust crate surface area warrants reproducible builds. |

## PQC-focused testing guidance

As PQC code lands, developers should add a dedicated validation loop covering:

- Rust unit tests in `rust/shekyl-crypto-pq`
- FFI ABI tests in `rust/shekyl-ffi`
- transaction serialization tests for the reboot-only PQ transaction format
- wallet sign/core verify integration tests
- malformed signature and malformed length rejection tests
- encoded-size regression checks for mempool, RPC, and ZMQ consumers

## Running core_tests

The `core_tests` binary exercises consensus rules, chain switching, double-spend
detection, Bulletproofs+ validation, and txpool behavior through the `chaingen`
event-replay framework.

```bash
# Build and run all core_tests
cmake --build build/ --target core_tests -- -j"$(nproc)"
build/tests/core_tests/core_tests --generate_and_play_test_data
```

Filter to a single test:

```bash
build/tests/core_tests/core_tests --generate_and_play_test_data --filter="gen_chain_switch_1"
```

### v3-from-genesis design

Shekyl's test suite is adapted for **v3-from-genesis**: all user transactions
are version 3 with mandatory PQC authentication (hybrid Ed25519 + ML-DSA-65).
Coinbase transactions also use version 3 (unified with regular txs). Key differences from upstream Monero:

- `FAKECHAIN` tests inject `--fixed-difficulty=1`
- Transaction construction helpers produce v3 with `use_view_tags=true`
- Coinbase outputs are indexed under `amount=0` for correct RCT spending
- Balance verification in callbacks uses RCT ecdhInfo decryption
- Economic constants (`TESTS_DEFAULT_FEE`, `FIRST_BLOCK_REWARD`) are
  calibrated for Shekyl's `COIN = 10^9` and `EMISSION_SPEED_FACTOR = 21`
- Several legacy tests incompatible with HF1-from-genesis are disabled
  (see `chaingen_main.cpp` comments)

Currently 80 tests are enabled and passing (including the re-enabled
`gen_block_reward` test whose reward verification was rewritten to use
Shekyl's four-component economics formula).

## Seed node build (lean daemon)

`make release-seed` builds only the daemon (`shekyld`) with hardware wallet
support disabled (`-DUSE_HW_DEVICE=OFF`) and `ARCH=x86-64` (portable x86_64).
This eliminates HIDAPI, protobuf, and libusb as runtime dependencies -- libraries
a seed node never needs -- and ensures the binary runs on any x86_64 host
regardless of CPU generation (no AVX/SSE4.x required).

```bash
make release-seed
```

The resulting binary is at `build/<platform>/release/bin/shekyld`.

Equivalent manual cmake invocation:

```bash
cmake -S . -B build/seed-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DARCH="x86-64" \
  -DUSE_HW_DEVICE=OFF \
  -DBUILD_TESTS=OFF
cmake --build build/seed-release --target daemon -- -j"$(nproc)"
```

If you previously configured the same build directory with a different `ARCH`
(for example `native`), delete that build directory before rebuilding so stale
CMake cache values cannot leak architecture-specific flags.

**Runtime dependencies** for a seed-built binary are reduced to:

- Boost (chrono, date-time, filesystem, program-options, regex, serialization,
  system, thread)
- OpenSSL, ZeroMQ, libunbound, libsodium, readline, expat

No HIDAPI, protobuf, or libusb packages are required on the target machine.

See `shekyl-dev/docs/SEED_NODE_DEPLOYMENT.md` for full deployment instructions.

## Testnet build command cookbook

Use out-of-source builds and keep a dedicated release directory for testnet.

### 1) Configure once (fresh testnet release build dir)

```bash
cmake -S . -B build/testnet-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=ON
```

If dependencies changed, rerun the configure command before building.

### 2) Build everything (full compile)

```bash
cmake --build build/testnet-release -- -j"$(nproc)"
```

Equivalent target-explicit form:

```bash
cmake --build build/testnet-release --target all -- -j"$(nproc)"
```

### 3) Build only specific executables/components

Daemon only:

```bash
cmake --build build/testnet-release --target daemon -- -j"$(nproc)"
```

Wallet CLI:

```bash
cmake --build build/testnet-release --target simplewallet -- -j"$(nproc)"
```

Wallet RPC:

```bash
cmake --build build/testnet-release --target wallet_rpc_server -- -j"$(nproc)"
```

Primary C++ test binaries:

```bash
cmake --build build/testnet-release --target unit_tests core_tests -- -j"$(nproc)"
```

Useful utilities:

```bash
cmake --build build/testnet-release --target \
  blockchain_export blockchain_import blockchain_stats gen_multisig -- -j"$(nproc)"
```

Note: if your environment reports an issue with the aggregate `tests` meta-target,
build `unit_tests` and `core_tests` directly as shown above.

### 4) Verify available targets in your build dir

```bash
cmake --build build/testnet-release --target help
```

### 5) Fast recovery when you hit many compile errors

Common fix sequence for stale/generated artifacts:

```bash
rm -rf build/testnet-release
cmake -S . -B build/testnet-release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build/testnet-release --target daemon -- -j"$(nproc)"
```

### 6) Testnet launch sanity command (runtime, not build)

```bash
./build/testnet-release/bin/shekyld --testnet --non-interactive --data-dir /var/lib/shekyl-testnet
```
