# Shekyl Changelog

## Unreleased

### ✨ Added

- **Release builds for macOS, Linux aarch64, and FreeBSD.** The
  `release/tagged` workflow now cross-compiles and publishes `.tar.gz`
  archives for macOS x86_64, macOS aarch64, Linux aarch64, and FreeBSD
  x86_64 alongside the existing Linux x86_64 and Windows x64 packages.
- **Linux aarch64 `.deb` and `.rpm` packages.** The cross-compiled ARM64
  build now produces Debian and RPM packages (with systemd unit) in
  addition to the portable tarball, matching the x86_64 packaging.
- **Source archive in GitHub Releases.** A new `source-archive` job
  produces `shekyl-vX.Y.Z-source.tar.gz` containing the full source tree
  with all submodules, attached to each release alongside the binaries.

### 🔄 Changed

- **Gitian reproducible builds: migrated from Ubuntu 18.04 (Bionic) to 22.04
  (Jammy).** All five build descriptors (`gitian-linux.yml`, `gitian-win.yml`,
  `gitian-osx.yml`, `gitian-android.yml`, `gitian-freebsd.yml`),
  `gitian-build.py`, and `dockrun.sh` now target Jammy. Drops GCC 7 and
  Python 2 dependencies in favour of the distro-default GCC 11 and Python 3.
  Upgrades FreeBSD cross-compiler from Clang 8 to Clang 14. Removes
  Bionic-specific workarounds (i686 asm symlink hack, glibc `math-finite.h`
  hack). Adds `linux-libc-dev:i386` for native i686 headers. C++17 is now
  fully supported by the Gitian toolchain.

### 🐛 Fixed

- **Gitian: enable `universe` repository in Docker base image.** The
  `ubuntu:jammy` Docker image only enables `main restricted` by default;
  `gitian-build.py` now patches the base image after `make-base-vm` to add
  `universe`, fixing installation of `faketime`, `bsdmainutils`, and other
  packages that moved out of `main`. Uses `docker build` (not run+commit)
  to preserve the image's CMD/USER metadata so `gbuild` containers stay
  running.
- **Gitian Linux: fix i386-dependent package installation.** The i386
  architecture is now enabled in the Docker base image (via `gitian-build.py`'s
  `docker build` step) along with passwordless `sudo` for the `ubuntu` user,
  allowing `linux-libc-dev:i386`, `gcc-multilib`, and `g++-multilib` to be
  installed normally via the descriptor's `packages:` section.
- **Gitian macOS: add `libtinfo5` and `python-is-python3`, remove `python`
  from `FAKETIME_PROGS`.** The pre-built Clang 9 cross-compiler requires
  `libtinfo.so.5`. The `python` faketime wrapper broke CMake's
  `FindPythonInterp` version detection in the `native_libtapi` build (empty
  `PYTHON_VERSION_STRING`); removing `python` from the faketime wrappers
  fixes this while preserving timestamp reproducibility for `ar`, `ranlib`,
  `date`, `dmg`, and `genisoimage`.
- **Gitian Android: add `python-is-python3`.** Android NDK r17b scripts use
  `#!/usr/bin/env python` which does not exist on Jammy without this package.
- **Gitian macOS: fix Rust `ring` crate cross-compilation.** `BuildRust.cmake`
  incorrectly overrode the macOS cross-compiler with the Linux system `clang`
  when cross-compiling for Darwin, causing the `ring` crate to include
  Linux-only `cet.h`. Now only uses system clang on native macOS builds.
- **Gitian Windows: drop i686 (32-bit) target.** The i686-pc-windows-gnu Rust
  target has an unresolved `GetHostNameW@8` symbol against MinGW's `ws2_32`.
  Since the release workflow only targets x86_64, the 32-bit Gitian build is
  removed.
- **macOS cross-build: exclude `-fcf-protection=full`.** Intel CET is x86
  Linux only; the flag defines `__CET__` which triggers `#include <cet.h>` in
  the `ring` crate's assembly, but `cet.h` does not exist in the macOS SDK.
  Now excluded for all Apple targets.
- **macOS aarch64 cross-build: set `MACOSX_DEPLOYMENT_TARGET=10.16`.**
  Clang 9 (depends cross-compiler) does not recognise macOS version 11.0+.
  Apple aliases 10.16 == 11.0; the `cc-rs` crate respects this env var, fixing
  the `ring` build for `aarch64-apple-darwin`.
- **Gitian Docker base image: install `sudo` before creating sudoers entry.**
  The `/etc/sudoers.d/` directory does not exist in the minimal Ubuntu image
  until the `sudo` package is installed.

### 🔄 Changed

- **Replace C++20 designated initializers with C++17-compatible member
  assignment.** Rewrote 10 call sites in `cryptonote_core.cpp`,
  `blockchain.cpp`, `levin_notify.cpp`, `multisig_tx_builder_ringct.cpp`, and
  `wallet2.cpp`. GCC/Clang accepted these as extensions; MSVC rejects them.
- **Replace `__thread` with `thread_local` in easylogging++.** The
  `__thread` qualifier is GCC/Clang-specific; `thread_local` (C++11) is
  portable across GCC, Clang, and MSVC.
- **Centralize `ssize_t` typedef in `src/common/compat.h`.** Replaces
  duplicate `#if defined(_MSC_VER)` guards in `util.h` and `download.h`
  with a single include.

### 🗑️ Removed

- **Gitian Android build.** Removed from the Gitian matrix since there is no
  Android wallet. The Android NDK r17b is also incompatible with Ubuntu Jammy.
- **Gitian Linux: drop i686-linux-gnu (32-bit x86) target.** Eliminates the
  need for `linux-libc-dev:i386`, `gcc-multilib`, `g++-multilib`, `sudo`,
  and the `dpkg --add-architecture i386` workaround. Simplifies the Docker
  base image patching to only enable the `universe` repository.

### 📚 Documentation

- **`docs/RELEASING.md`: document all release artifacts.** Updated the
  artifact table to list all 13 files produced per release (was 6),
  including cross-platform tarballs, aarch64 `.deb`/`.rpm`, and source
  archive. Updated "Future Platforms" to reflect that macOS tarballs are
  now shipping and `.dmg`/AppImage remain planned.

## [3.0.3-RC1] - 2026-03-31

### Known Limitations

- **Multisig not yet implemented.** Multisig wallets are restricted to v2
  transactions (no PQC authentication). PQC-enabled multisig is planned for
  a future release. See `docs/PQC_MULTISIG.md` for the design.

### ✨ Added

- **Rust wallet RPC server (`shekyl-wallet-rpc`)**: New Rust crate that
  replaces the C++ `wallet_rpc_server` with an axum-based JSON-RPC server.
  Calls the existing C++ `wallet2` library through a new C FFI facade
  (`wallet2_ffi.cpp/.h`). Supports all 98 RPC methods with full parity.
  Can run as a standalone binary (`shekyl-wallet-rpc-rs`) or be embedded
  as a library in the Tauri GUI wallet. See `docs/WALLET_RPC_RUST.md`.

- **C++ wallet2 FFI facade (`wallet2_ffi.cpp/.h`)**: Opaque-handle C API
  over `wallet2` with JSON serialization at the boundary. Includes a
  generic `wallet2_ffi_json_rpc()` dispatcher that routes all RPC methods
  to the underlying wallet2 implementation. Covers lifecycle, queries,
  transfers, sweeps, proofs, accounts, address book, import/export,
  multisig, staking, mining, background sync, and daemon management.

- **GUI wallet direct FFI integration**: The Tauri GUI wallet now calls
  wallet2 directly through the Rust FFI bridge (`wallet_bridge.rs`)
  instead of spawning a child `shekyl-wallet-rpc` process and
  communicating via HTTP. Eliminates process management, port allocation,
  and HTTP overhead. Removed `wallet_process.rs` and `wallet_rpc.rs`.

### v3-First Core Test Adaptation

- **Enforced min_tx_version=3 for non-coinbase transactions**: All user
  transactions in the test suite now construct v3 with PQC authentication
  (hybrid Ed25519 + ML-DSA-65). Coinbase transactions remain v2.
- **Adapted chaingen framework for RCT-from-genesis**: Transaction
  construction helpers (`construct_tx_to_key`, `construct_tx_rct`) thread
  `hf_version=1` and `use_view_tags=true`. Coinbase outputs are indexed
  under `amount=0` for correct RCT spending. Fixed difficulty is injected
  for FAKECHAIN replay. Mixin checks are relaxed for FAKECHAIN.
- **Added RCT-aware balance verification**: Pool transaction balance checks
  in `gen_chain_switch_1` now decrypt ecdhInfo amounts using the recipient's
  view key instead of relying on the plaintext `o.amount` field (always 0
  for RCT outputs).
- **Recalibrated economic constants for Shekyl**: Test constants
  (`TESTS_DEFAULT_FEE`, `FIRST_BLOCK_REWARD`, `MK_COINS`) match Shekyl's
  `COIN = 10^9`, `EMISSION_SPEED_FACTOR = 21`, and staker/burn splits.
  `construct_miner_tx_manually` in block validation tests uses Shekyl's
  reward distribution.
- **Fixed Bulletproofs+ test suite**: Dynamically discover miner output
  amounts, set HF to 1 for all block construction, correctly flag coinbase
  outputs as RCT. All 15 BP+ tests pass.
- **Fixed txpool tests**: Adjusted key image count assertions for
  multi-input RCT transactions and corrected unlock_time handling.
- **Fixed double-spend tests**: Modified output selection to pick the
  largest decomposed output, avoiding underflow on fee subtraction.
- **Disabled legacy-incompatible tests**: `gen_block_invalid_binary_format`
  (hours-long), `gen_block_invalid_nonce`, `gen_block_late_v1_coinbase_tx`,
  `gen_uint_overflow_1`, `gen_block_reward`,
  `gen_bpp_tx_invalid_before_fork`, `gen_bpp_tx_invalid_clsag_type`,
  `gen_ring_signature_big`. These rely on pre-RCT economics, legacy
  fork transitions, or are prohibitively slow.
- **All 79 core_tests pass with 0 failures.**

### Test suite cleanup for Shekyl HF1

- **Removed 96 dead Borromean ringct tests**: All tests in
  `tests/unit_tests/ringct.cpp` that exercised legacy Borromean range
  proofs were removed. Shekyl HF1 rejects Borromean proofs at the
  `genRctSimple` level. Retained 9 non-Borromean tests (CLSAG, HPow2,
  d2h, d2b, key_ostream, zeroCommit, H, mul8).
- **Updated transaction construction helpers to Bulletproofs+**: The
  `test::make_transaction` helper (used by JSON serialization and ZMQ
  tests) now constructs transactions with
  `{ RangeProofPaddedBulletproof, 4 }` (BP+/CLSAG) instead of the
  removed Borromean or unsupported BP v2 configs. Removed the obsolete
  `bulletproof` parameter. Consolidated three JSON serialization tests
  (RegularTransaction, RingctTransaction, BulletproofTransaction) into
  one `BulletproofPlusTransaction` test. Fixes all 8 zmq_pub/zmq_server
  test failures.
- **Updated serialization round-trip test to BP+**: Changed
  `Serialization.serializes_ringct_types` from `bp_version 2` (throws
  "Unsupported BP version") to `bp_version 4` (Bulletproofs+). Updated
  assertions from MGs to CLSAGs and from `bulletproofs` to
  `bulletproofs_plus`.
- **Removed legacy Monero-era core/perf test executions**: Stopped running
  deprecated Borromean/pre-RCT/fork-transition test generators in
  `core_tests` and removed Borromean/MLSAG/range-proof performance test
  invocations and defaults, so CI validates HF1-era behavior only.
- **Hardened block-weight test contract for HF1 semantics**: `block_weight`
  comparison now enforces deterministic `H/BW/LTBW` parity and EMBW floor
  invariants instead of byte-identical legacy model output, preventing
  false failures from non-consensus median implementation details.
- **Fixed block_reward test expected values**: Updated emission curve
  expectations to match Shekyl's `EMISSION_SPEED_FACTOR = 21` (120s
  blocks) and per-block tail floor of
  `FINAL_SUBSIDY_PER_MINUTE * target_minutes`.
- **Rewrote mining_parity release multiplier test**: Replaced legacy
  pre-Shekyl-NG equality assertion (which tested a non-existent version
  0) with a test that verifies the release multiplier correctly scales
  rewards above and below the tx volume baseline.
- **Fixed Ubuntu 24.04 CI test runner**: Replaced `pip install` with
  `apt install python3-*` packages to comply with PEP 668
  (externally-managed-environment).

### 🐛 Fixed

- **macOS cross-compilation (depends CI)**: Fixed multiple build failures
  for Cross-Mac x86_64 and Cross-Mac aarch64 targets:
  - Raised macOS minimum deployment target from 10.8 (Mountain Lion, 2012)
    to 10.15 (Catalina, 2019) to enable `std::filesystem` support in the
    cross-compiled libc++.
  - Fixed Boost discovery in depends builds by setting `Boost_NO_BOOST_CMAKE`
    and forcing MODULE mode, preventing `BoostConfig.cmake` variant-check
    failures on cross-compiled Darwin libraries.
  - Made `boost_locale` a conditional dependency (Windows only), since it
    is only used within `#ifdef WIN32` blocks and was unavailable for
    Darwin cross-builds.
  - Added per-target `CC_<triple>/AR_<triple>/CFLAGS_<triple>` environment
    variables in `BuildRust.cmake` so the `ring` crate can locate the
    cross-compiler for C/assembly code.
  - Used system clang (instead of the depends-bundled Clang 9) for Rust
    crate C compilation on Darwin, since `ring` 0.17 requires clang
    features unavailable in Clang 9 (macOS 11 version strings,
    `-fno-semantic-interposition`).
  - Guarded `-fno-semantic-interposition` behind `check_c_compiler_flag()`
    so it is only added when the compiler supports it (Clang 9 does not).
  - Fixed OSX SDK cache key in `depends.yml` to include the SDK version
    and skip the cache step for non-macOS builds.

- **FreeBSD cross-compilation (depends CI)**: Fixed multiple build failures
  for the x86_64 FreeBSD target:
  - Switched Boost's b2 toolset from `gcc` to `clang` for FreeBSD, fixing
    C++ standard library header resolution (`<cstddef>` not found).
  - Embedded `-stdlib=libc++` in the FreeBSD clang++ wrapper script so all
    depends packages automatically use the correct C++ standard library,
    regardless of whether their own `$(package)_cxxflags` overrides the
    host flags (previously broke zeromq, sodium, and other packages).
  - Fixed compiler wrapper argument quoting: replaced the broken
    `echo "...$$$$""@"` pattern with `printf '..."$$$$@"'` so `"$@"`
    passes through correctly to the generated wrapper, preventing argument
    mangling for flags containing quotes (e.g. `-DPACKAGE_VERSION="1.0.20"`).
  - Added `-D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION` to both
    Boost's FreeBSD cxxflags and the CMake toolchain, restoring
    `std::unary_function` compatibility needed by Boost 1.74's
    `container_hash/hash.hpp` under FreeBSD's strict C++17 libc++.
  - Removed the unsupported `no-devcrypto` option from OpenSSL's FreeBSD
    configure flags (the devcrypto engine was removed in OpenSSL 3.0).
  - Added `threadapi=pthread runtime-link=shared` to Boost's FreeBSD
    config options for correct threading and linking behavior.

- **Linux static release build (libudev linking)**: Added `libudev-dev` to
  the `release-tagged.yml` CI package list. Static `libusb-1.0.a` and
  `libhidapi-libusb.a` depend on `libudev` for USB hotplug support;
  without the dev package installed, `find_library(udev)` failed and the
  final link produced undefined `udev_*` references, preventing the
  "Publish GitHub Release" step from running.
- **Win64 build failure (ICU generator expression)**: Replaced broken CMake
  generator expressions `$<$<BOOL:${WIN32}>:${ICU_LIBRARIES}>` with
  `if(WIN32)` blocks in `simplewallet`, `wallet_api`, and
  `libwallet_api_tests` CMakeLists. Generator expressions cannot contain
  semicolon-separated lists; the old pattern passed literal fragments like
  `$<1:icuio` to the linker on MinGW cross-compilation.
- **Linux static build (libunbound linking)**: Fixed `FindUnbound.cmake`
  scoping bug where `list(APPEND UNBOUND_LIBRARIES ...)` created a local
  variable shadowing the `find_library` cache entry. The transitive static
  deps (libevent, libnettle, libhogweed, libgmp) were silently dropped,
  causing undefined reference errors in `release-static-linux-x86_64`
  builds.
- **JSON serialization of v3 (PQC) transactions**: Added missing
  `pqc_auth` field to the RapidJSON `toJsonValue`/`fromJsonValue`
  roundtrip for `cryptonote::transaction`. V3 transactions created
  under `HF_VERSION_SHEKYL_NG` include a `pqc_authentication`
  envelope; without JSON support the field was silently dropped,
  causing `get_transaction_hash` to fail with "Inconsistent
  transaction prefix, unprunable and blob sizes" after a JSON
  roundtrip. Fixes the `JsonSerialization.BulletproofPlusTransaction`
  unit test failure.

### GUI Wallet

- New project: Shekyl GUI Wallet (`shekyl-gui-wallet`) at
  [Shekyl-Foundation/shekyl-gui-wallet](https://github.com/Shekyl-Foundation/shekyl-gui-wallet).
  Built with Tauri 2 (Rust backend) + Vite + React 19 + TypeScript + Tailwind CSS 4.
  Initial scaffold includes 6 pages (Dashboard, Send, Receive, Staking,
  Transactions, Settings), stub Tauri commands, Shekyl gold/purple design system,
  and verified production builds for Linux (.deb, .rpm, .AppImage).
  Phase 2 will add the C++ FFI bridge to `wallet2_api.h` for real wallet operations.
- Added testing infrastructure: Vitest + React Testing Library for frontend
  (20 tests across 6 suites), cargo test for Rust backend (10 tests), with
  Tauri IPC mocking for isolated component testing.
- Added CI/CD via GitHub Actions: `ci.yml` runs ESLint, TypeScript type-check,
  Vitest, Rustfmt, Clippy, and cargo test on every PR; `release.yml` builds
  multi-platform binaries (Linux x64, Windows x64, macOS ARM64 + Intel) via
  `tauri-action` and creates draft GitHub releases.

### Consensus timing alignment (HF1)

- Fixed remaining runtime paths that still derived timing from legacy `DIFFICULTY_TARGET_V1` (`60s`) so active Shekyl HF1 behavior consistently uses `DIFFICULTY_TARGET_V2` (`120s`) for difficulty target selection, block reward minute-scaling, unlock-time leeway checks, sync ETA reporting, and wallet lock-time display.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to mark the 120s block-time drift item as resolved (`code_fix_required` completed).

### 📚 Documentation

- Updated `docs/V3_ROLLOUT.md` to reflect HF1 (genesis) activation instead
  of the stale HF17 references. Added v3-first test strategy section.
- Updated `docs/POST_QUANTUM_CRYPTOGRAPHY.md` scheme_id status table and
  deferred-items section from HF17 to HF1.
- Updated `docs/PQC_MULTISIG.md` V3 signature list heading from HF17 to HF1.
- Updated `docs/STAKER_REWARD_DISBURSEMENT.md` to reference HF1 activation.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` HF naming drift label
  from `doc_correction` to resolved.
- Added `core_tests` section to `docs/COMPILING_DEBUGGING_TESTING.md`
  documenting the v3-from-genesis test approach and how to run/filter tests.

### Genesis initialization compatibility

- Regenerated `GENESIS_TX` for mainnet, testnet, and stagenet to modern coinbase format (`tx.version = 2`) with tagged outputs.
- Removed all legacy genesis compatibility exceptions and enforced strict coinbase version checks (`tx.version > 1`) across all network types, including `FAKECHAIN`.
- Fixed genesis reward validation to accept the hardcoded `GENESIS_TX` amount at `height == 0` while leaving post-genesis reward accounting unchanged.
- Fixed startup edge case where long-term weight median calculations could evaluate with zero historical blocks during genesis initialization (`count == 0`), causing daemon boot failure on empty data dirs.
- Updated genesis-construction helper (`build_genesis_coinbase_from_destinations`) to emit `tx.version = 2` with view-tagged outputs for current HF1 expectations.
- Added canonical root build command `make genesis-builder` (using the main release build dir with `GENESIS_TOOL_SRC_DIR`) to avoid split/ambiguous genesis-builder binaries across multiple build trees.

### Testnet economy readiness checks

- Added `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to track design-vs-code status for economy testnet rehearsal with explicit drift tags (`doc_correction`, `code_fix_required`, `needs_decision`).
- Added `scripts/check_testnet_genesis_consensus.py` to verify multi-node testnet tuple consistency (`height 0 block hash`, `miner tx hash`, `tx hex`) and optional economy field presence in `get_info`.
- Added Rust parity/invariant tests:
  - `shekyl-economics-sim`: validates `SimParams::default()` against `config/economics_params.json`.
  - `shekyl-economics`: added release monotonicity, burn bounds, and emission-share monotonicity tests.
  - `shekyl-ffi`: added direct FFI-vs-Rust consistency tests for burn pct and emission share.
- Added functional RPC test `tests/functional_tests/economy_info.py` and included it in `functional_tests_rpc.py` default test list to assert required economy fields are exposed by `get_info`.
- Corrected documentation errors without changing design intent:
  - Clarified `DESIGN_CONCEPTS.md` Section 2 as historical baseline.
  - Removed duplicate heading in `GENESIS_TRANSPARENCY.md`.
  - Linked `RELEASE_CHECKLIST.md` testnet section to the rehearsal runbook/checklist and deterministic tuple check command.

### BREAKING: Second-pass rebrand (wallet, URI, serialization)

- **URI scheme**: Wallet URI generation and parsing now use `shekyl:` only.
  The legacy `monero:` scheme is no longer accepted. QR codes and payment
  links generated by previous builds will fail to parse. Regenerate all
  payment URIs before upgrading wallets.
- **Wallet/export/cache magic strings**: All file-format magic prefixes have
  been rewritten from `Monero` to `Shekyl`:
  - `UNSIGNED_TX_PREFIX` → `"Shekyl unsigned tx set\005"`
  - `SIGNED_TX_PREFIX` → `"Shekyl signed tx set\005"`
  - `MULTISIG_UNSIGNED_TX_PREFIX` → `"Shekyl multisig unsigned tx set\001"`
  - `KEY_IMAGE_EXPORT_FILE_MAGIC` → `"Shekyl key image export\003"`
  - `MULTISIG_EXPORT_FILE_MAGIC` → `"Shekyl multisig export\001"`
  - `OUTPUT_EXPORT_FILE_MAGIC` → `"Shekyl output export\004"`
  - `ASCII_OUTPUT_MAGIC` → `"ShekylAsciiDataV1"`
  - Wallet cache magic → `"shekyl wallet cache"`
  Old wallet caches, exported key images, multisig exports, signed/unsigned
  tx sets, and output exports are **incompatible** and must be re-exported
  after upgrading.
- **Message signing domain**: `HASH_KEY_MESSAGE_SIGNING` changed from
  `"MoneroMessageSignature"` to `"ShekylMessageSignature"`. Messages signed
  with the old domain separator will fail verification.
- **i18n domain**: Translation catalogue domain changed from `"monero"` to
  `"shekyl"`.
- **Daemon stdout redirect**: Daemonized output file changed from
  `bitmonero.daemon.stdout.stderr` to `shekyl.daemon.stdout.stderr`.
- **Log file names**: All blockchain utility log files renamed from
  `monero-blockchain-*` to `shekyl-blockchain-*`.
- **DNS seed/checkpoint domains**: Replaced `moneroseeds.*` and
  `moneropulse.*` lookups with 5-domain consensus set: `shekyl.org`,
  `shekyl.net`, `shekyl.com`, `shekyl.biz`, `shekyl.io`. Majority
  threshold is 3 of 5. See `shekyl-dev/docs/DNS_CONFIG.md` for the full
  infrastructure reference.
- **Update check**: Software name comparison for macOS `.dmg` extension
  switched from `monero-gui` to `shekyl-gui`.
- **Hardware wallet**: Ledger app error message now references "Shekyl Ledger
  App" instead of "Monero Ledger App". Trezor protobuf namespaces are
  unchanged (third-party protocol dependency).
- **Intentionally preserved**: Trezor/Ledger protobuf includes and protocol
  namespaces (`hw.trezor.messages.monero.*`), Esperanto mnemonic word
  `"monero"` (means "money"), academic paper citations, copyright headers,
  `MONERO_DEFAULT_LOG_CATEGORY` build-internal macros, and `MakeCryptoOps.py`
  build artifacts.

#### Operator migration checklist

1. Delete old wallet cache files (`.keys` files are unaffected).
2. Re-export any key-image, multisig, or output export files.
3. Re-export and re-sign any unsigned/signed transaction sets.
4. Regenerate all `monero:` QR codes/payment URIs as `shekyl:` URIs.
5. Update any scripts or integrations that parse URI scheme or file magic.
6. Verify message signatures were not created with the old signing domain.
7. Update log rotation configs if they reference `monero-blockchain-*` paths.
8. Update DNS infrastructure to serve records under all 5 TLDs (`.org`,
   `.net`, `.com`, `.biz`, `.io`). See `shekyl-dev/docs/DNS_CONFIG.md`.

### Dead Monero legacy code removal

- **Dead HF branch cleanup**: Collapsed all always-true / always-false hard fork
  version branches across `blockchain.cpp` (~25 sites), `wallet2.cpp` (~22 sites),
  `cryptonote_basic_impl.cpp` (2 sites), and `cryptonote_core.cpp` (2 sites).
  Since all `HF_VERSION_*` constants are 1, every `hf_version >= HF_VERSION_*`
  was always true and every `hf_version < HF_VERSION_*` was always false.
  Collapsed fee algorithms, ring size ladders, tx version ladders, difficulty
  target selection, sync block size selection, BP/CLSAG/BP+ gating, dynamic
  fee scaling, long-term block weight calculations, and `use_fork_rules()` call
  sites. Removed ~500-800 lines of dead conditional logic.

- **Dropped v1 transaction support entirely**:
  - **Consensus**: `check_tx_outputs` now rejects `tx.version == 1` outright.
    `check_tx_inputs` sets `min_tx_version = 2` unconditionally; unmixable
    output counting and ring-size exemptions removed. v1 ring signature
    verification code and threaded v1 signature checking removed from
    `check_tx_inputs`. `expand_transaction_2` only handles CLSAG and
    BulletproofPlus; old RCTTypeFull/Simple/Bulletproof/Bulletproof2 branches
    removed.
  - **RingCT** (`rctSigs.cpp`/`.h`): Removed ~770 lines of dead crypto code:
    `genBorromean`, `verifyBorromean`, `MLSAG_Gen`, `MLSAG_Ver`, `proveRange`,
    `verRange`, `proveRctMG`, `proveRctMGSimple`, `verRctMG`, `verRctMGSimple`,
    `populateFromBlockchain`, `genRct` (both overloads), `verRct`, `decodeRct`
    (both overloads). `genRctSimple`, `verRctSemanticsSimple`,
    `verRctNonSemanticsSimple`, and `decodeRctSimple` only accept
    `RCTTypeCLSAG` and `RCTTypeBulletproofPlus`. Header reduced from 144 to
    87 lines.
  - **Transaction construction** (`cryptonote_tx_utils.cpp`): Removed v1
    ring signature generation block and non-simple RCT construction
    (`genRct`). All transactions now use `genRctSimple` (CLSAG path).
  - **Tx verification utils**: Removed `RCTTypeSimple`, `RCTTypeFull`,
    `RCTTypeBulletproof`, `RCTTypeBulletproof2` from batch semantics
    verification.
  - **Test fixups**: Updated all test files under `tests/` to match the
    removed RCT primitives. Stubbed performance benchmarks for MLSAG
    (`rct_mlsag.h`, `sig_mlsag.h`) and Borromean range proofs
    (`range_proof.h`). Replaced `verRct` with `verRctNonSemanticsSimple`
    in `check_tx_signature.h`. Removed `decodeRct` else-branches from
    `rct.cpp`, `rct2.cpp`, `bulletproofs.cpp`, `bulletproof_plus.cpp`.
    In `unit_tests/ringct.cpp`: removed Borromean, MLSAG, and
    RCTTypeFull-only tests; rewrote `make_sample_rct_sig` to use
    `genRctSimple`; replaced all `verRct` calls with `verRctSimple`.

- **Wallet v1 cleanup**: Removed unmixable sweep functions, v1 fee/amount
  paths, v1 coinbase optimization, dead non-RCT creation branches, and
  replaced `RangeProofBorromean` defaults with `RangeProofPaddedBulletproof`.
  `sweep_dust` RPC returns error; `createSweepUnmixableTransaction` API
  returns empty result with error status.

- **Trezor Shekyl rebrand**: Renamed all include guard macros from
  `MONERO_*_H` to `SHEKYL_*_H` in 8 `device_trezor/` headers. Updated
  derivation path comment and HTTP Origin URL. Protobuf message types and
  wire protocol identifiers intentionally preserved (must match Trezor
  firmware definitions).

### Epee Phase 1: Rust replacement for security-critical primitives

- **SSL certificate generation migrated to Rust (`rcgen`)**: Replaced the
  deprecated OpenSSL RSA/EC_KEY certificate generation in `net_ssl.cpp` with
  Rust's `rcgen` crate (ECDSA P-256) via FFI. Eliminates all `RSA_new`,
  `RSA_generate_key_ex`, `EC_KEY_new`, `EC_KEY_generate_key`, and other
  OpenSSL 3.0-deprecated API calls. The `create_rsa_ssl_certificate` and
  `create_ec_ssl_certificate` functions are replaced by a single
  `create_ssl_certificate` that delegates to `shekyl_generate_ssl_certificate`
  in the Rust FFI, returning PEM-encoded key+cert for loading into OpenSSL's
  SSL_CTX via non-deprecated BIO APIs.
- **Post-quantum hybrid key exchange enabled**: TLS context configuration now
  prefers `X25519MLKEM768` (FIPS 203 ML-KEM-768 hybrid) key exchange groups,
  falling back to classical `X25519:P-256:P-384` when the OpenSSL build lacks
  PQ support. Also added explicit TLS 1.3 ciphersuite configuration. Removed
  deprecated `SSL_CTX_set_ecdh_auto` call.
- **Secure memory wiping migrated to Rust (`zeroize`)**: Replaced the
  platform-specific `memwipe.c` implementation (memset_s / explicit_bzero /
  compiler-barrier fallback) with a single call to the Rust `zeroize` crate
  via `shekyl_memwipe` FFI. The `zeroize` crate uses `write_volatile` which
  is guaranteed not to be optimized away, replacing the fragile compiler
  barrier tricks.
- **Memory locking migrated to Rust (`libc`)**: Replaced the GNUC-only
  `mlock`/`munlock`/`sysconf` calls in `mlocker.cpp` with Rust FFI functions
  (`shekyl_mlock`, `shekyl_munlock`, `shekyl_page_size`) backed by the `libc`
  crate. Adds Windows `VirtualLock`/`VirtualUnlock` support that was
  previously missing (`#warning Missing implementation`). The `mlocked<T>` and
  `scrubbed<T>` C++ template wrappers are preserved unchanged.
- **New Rust FFI dependencies**: Added `rcgen = "0.14"`, `zeroize = "1"`,
  `libc = "0.2"` to `shekyl-ffi/Cargo.toml`.
- **C-compatible FFI header**: Added `src/shekyl/shekyl_secure_mem.h` with
  C-linkage declarations for the secure memory primitives, usable from both
  C (`memwipe.c`) and C++ (`mlocker.cpp`) translation units.
- **CMake wiring**: `epee` library now links `${SHEKYL_FFI_LINK_LIBS}` and
  includes `${CMAKE_SOURCE_DIR}/src` for the FFI headers.

### Build fixes

- **Boost CONFIG-mode compatibility shim**: When Boost is found via cmake
  CONFIG mode (Boost 1.85+), old-style `${Boost_XXX_LIBRARY}` variables may
  resolve to versioned `.so` paths that don't exist on rolling-release distros
  (e.g. Arch Linux with Boost 1.90). Added a shim in the root `CMakeLists.txt`
  that remaps all `Boost_*_LIBRARY` variables to `Boost::*` imported targets
  when CONFIG mode is active. Fixes linker failures on Arch.
- **Removed duplicate `parse_amount` test**: Two identical
  `TEST_pos(18446744073709551615, ...)` entries in
  `tests/unit_tests/parse_amount.cpp` caused a redefinition error on macOS
  Clang. Removed the duplicate.
- **Boost CONFIG-mode validation**: Added a cmake-configure-time check that
  verifies Boost imported-target `IMPORTED_LOCATION` files exist on disk.
  Gives a clear `FATAL_ERROR` with remediation steps instead of a cryptic
  linker failure minutes into the build.
- **Arch Linux CI**: Added `boost-libs` to the Arch pacman install to
  provide shared `.so` files alongside the `boost` headers/cmake-config
  package.
- **Ubuntu 24.04 test matrix**: Added Ubuntu 24.04 to the `test-ubuntu`
  CI matrix (previously only 22.04 was tested).

### Depends system updates

- **FreeBSD sysroot updated to 14.4-RELEASE**: The cross-compilation
  sysroot was stuck at FreeBSD 11.3 (EOL Sept 2021), whose `base.txz`
  had been removed from FreeBSD mirrors (404). Updated to 14.4-RELEASE
  (March 2026), updated SHA256 hash, and fixed clang wrapper scripts
  from clang-8 to clang-14 to match `hosts/freebsd.mk`. Added
  `-stdlib=libc++` to CXXFLAGS and LDFLAGS since FreeBSD uses libc++
  and the Ubuntu host's clang-14 defaults to libstdc++. Also added
  `libc++-14-dev` and `libc++abi-14-dev` to CI packages for the FreeBSD
  cross-build so the host compiler can find libc++ headers when
  `-stdlib=libc++` is specified.
- **Boost: skip CONFIG mode for depends builds**: The depends-built Boost
  1.74.0 installs CMake config files whose variant detection fails for
  darwin cross-builds (`boost_locale` reports "No suitable build variant").
  `find_package(Boost ... CONFIG)` is now skipped when `DEPENDS` is true
  (set by the depends toolchain), falling back to the more robust MODULE
  mode (`FindBoost.cmake`).
- **OpenSSL: disabled `devcrypto` engine for FreeBSD**: Added
  `no-devcrypto` to FreeBSD OpenSSL configure options. The `/dev/crypto`
  engine requires the `crypto/cryptodev.h` kernel header which is not
  available in a cross-compilation sysroot.
- **libsodium updated to 1.0.20**: The 1.0.18 tarball was removed from
  `download.libsodium.org` (404). Updated to 1.0.20 with new SHA256 hash.
  Removed the 1.0.18-specific patches (`fix-whitespace.patch`,
  `disable-glibc-getrandom-getentropy.patch`) which no longer apply.

### Warning cleanup and dead code removal

- **Removed dead fork helpers**: Deleted unused `get_bulletproof_fork()`,
  `get_bulletproof_plus_fork()`, and `get_clsag_fork()` from `wallet2.cpp`.
  These Monero-era version ladders had no call sites; Shekyl activates all
  features from HF1.
- **Removed dead variable**: Deleted unused `bool refreshed` in
  `wallet2::refresh()`.
- **Removed legacy `result_type` typedefs**: Deleted `using result_type = void`
  from `add_input` and `add_output` visitor structs in `json_object.cpp`. These
  were required by `boost::static_visitor` but are unused by `std::visit`.
- **Fixed uninitialized-variable warning**: Zero-initialized `local_blocks_to_unlock`
  and `local_time_to_unlock` in `wallet2::unlocked_balance_all()`.
- **Fixed aliasing cast in wallet serialization**: Replaced C-style cast of
  `m_account_tags` from `pair<serializable_map, vector>` to `pair<map, vector>&`
  with direct `.parent()` accessor, eliminating formal undefined behavior.
- **Suppressed epee warnings**: Added targeted `#pragma GCC diagnostic` guards
  for `-Wclass-memaccess` (memcpy into `mlocked<scrubbed<>>` in
  `keyvalue_serialization_overloads.h`) and `-Wstring-compare` (type_info
  comparisons in `portable_storage.h`).
- **Renamed test target**: `monero-wallet-crypto-bench` renamed to
  `shekyl-wallet-crypto-bench`.
- **Trezor Protobuf fixes**: Added `std::string()` wrapping for
  `GetDescriptor()->name()` calls in `messages_map.cpp/.hpp` to handle
  Protobuf 22+ returning `absl::string_view`/`std::string_view`. Added
  missing `<cstdint>` include to `exceptions.hpp`.

### Rust crypto infrastructure

- **New `shekyl-crypto-hash` crate**: Implements `cn_fast_hash` (Keccak-256
  with original padding, not SHA3) and `tree_hash` (Merkle tree) in Rust
  using `tiny-keccak`. Both functions produce byte-identical output to the
  C implementations in `src/crypto/hash.c` and `src/crypto/tree-hash.c`.
- **FFI exports**: `shekyl_cn_fast_hash` and `shekyl_tree_hash` exposed
  through `shekyl-ffi` with C-ABI declarations in `shekyl_ffi.h`. The C++
  side can now call Rust hashing alongside or instead of the C path.
- **Rust-preferred development rule**: Added `.cursor/rules/rust-preferred.mdc`
  establishing policy for gradual C++ to Rust migration: new modules in Rust,
  crypto primitives via RustCrypto crates, computational extraction to Rust
  behind FFI when modifying existing C++ modules.

### Hardfork reboot and testnet wallet readiness

- **Hardfork schedule rebooted**: All `HF_VERSION_*` constants collapsed to 1.
  The chain starts with all features active from genesis -- no legacy migration
  gates. Hardfork tables reduced to single-entry `{ 1, 1, 0, timestamp }` for
  all three networks (mainnet, testnet, stagenet).
- Removed all raw numeric HF version gates (`hf_version <= 3`, `>= 7`, `< 8`,
  `> 8`, etc.) from consensus and transaction construction code, replacing them
  with named `HF_VERSION_*` constants. Legacy Monero-era transition logic
  (borromean proofs, bulletproofs v1, grandfathered txs) removed.
- Coinbase transactions always v2 RCT with single output, zero dust threshold.
- **Staked outputs excluded from spendable balance**: `is_transfer_unlocked()`
  now returns false for staked outputs, preventing them from being selected
  during normal transfers. `balance_per_subaddress` and
  `unlocked_balance_per_subaddress` skip staked outputs.
- **Unstake transaction fixed**: `create_unstake_transaction` now passes matured
  staked output indices directly to `create_transactions_from`, properly using
  the actual staked UTXOs as transaction inputs with standard ring signatures.
- **Claim reward validation fixed**: `check_stake_claim_input` now looks up the
  real staked output from the blockchain DB to get the actual amount and tier,
  replacing the hardcoded `shekyl_stake_weight(0, 0)` placeholder.
- **New daemon RPC `estimate_claim_reward`**: computes per-output reward
  server-side using the accrual database, returning reward amount, tier, and
  staked amount. Wallet `estimate_claimable_reward` now calls this RPC instead
  of returning a hardcoded zero.
- **CLI improvements**: `balance` command now shows staked balance alongside
  liquid and unlocked balances. New `staking_info` command shows wallet staking
  overview (locked/matured output counts with tier and remaining lock blocks).
  `stake`, `unstake`, and `claim_rewards` commands now include daemon
  connectivity guards.
- **Wallet RPC fixes**: `unstake` response changed from single `tx_hash` to
  `tx_hash_list` array to support multi-transaction unstaking. `stake` request
  now accepts `account_index` parameter. New `get_staked_balance` RPC returns
  staked balance with locked/matured output counts.

### Post-quantum cryptography

- **Phase 4 wallet/core PQC wiring completed**: all v3 transaction construction
  paths now include hybrid Ed25519 + ML-DSA-65 signing via `pqc_auth`. Fixed
  `create_claim_transaction` (staking reward claims) which previously built v3
  transactions without PQC authentication, causing consensus rejection.
- PQC verification enforced in both mempool acceptance and block validation for
  all non-coinbase v3 transactions.
- Multisig wallets intentionally restricted to v2 transactions (no PQC); the
  PQC secret key is cleared on multisig creation with a documented design note.
- Aligned `POST_QUANTUM_CRYPTOGRAPHY.md` field naming: `hybrid_ownership_material`
  renamed to `hybrid_public_key` to match the canonical code implementation.
- Added three negative PQC test vectors (`docs/PQC_TEST_VECTOR_002–004`) covering
  tampered ownership material, wrong scheme_id, and oversized/truncated signature
  blobs. Each vector is generated and verified by integration tests in
  `rust/shekyl-crypto-pq/tests/negative_vectors.rs`.
- Reconciled `POST_QUANTUM_CRYPTOGRAPHY.md` Open Items: resolved Rust crate
  selection, `RctSigningBody` layout, ownership binding, and max tx size;
  only `scheme_id` registry extension remains open.
- Added tentative V4 PQC Privacy Roadmap to `POST_QUANTUM_CRYPTOGRAPHY.md`
  with four phases (V4-A Research, V4-B Prototype, V4-C Testnet,
  V4-D Activation) and explicit KEM composition decision milestone
  (`X25519 + ML-KEM-768` via `HKDF-SHA-512`).
- Added payload limit guidance section to `V3_ROLLOUT.md` with recommended
  minimum mempool/ZMQ/relay buffer sizes for post-PQC transactions.

### Economics and simulation

- Added `rust/shekyl-economics-sim` workspace crate: reproducible 8-scenario
  simulation harness driven from `config/economics_params.json`. Scenarios
  cover baseline, boom-bust, sustained growth, stuffing attack, stake
  concentration, mass unstaking, chain bootstrap, and late-chain tail state.
  Results archived in `docs/economics_sim_results.json`.
- Provisionally locked `tx_baseline` (50) and `FINAL_SUBSIDY_PER_MINUTE`
  (300,000,000) in `DESIGN_CONCEPTS.md` after simulation validation; pending
  final testnet confirmation.
- Wired live chain-health RPC fields in `get_info`: `release_multiplier` now
  computed from rolling `tx_volume_avg`, `burn_pct` from current chain state,
  `total_burned` persisted in LMDB and accumulated per block.
- Wired `total_staked` in `get_staking_info` via new
  `Blockchain::get_total_staked()` accessor backed by existing stake cache.
- Added `total_burned` LMDB persistence: `set_total_burned`/`get_total_burned`
  on `BlockchainDB`, with rollback support via extended `staker_accrual_record`
  (`actually_destroyed` field).

### Privacy and anonymity networks

- Updated `ANONYMITY_NETWORKS.md` with measured v3 payload impact analysis
  (cell/fragment counts for Tor and I2P), known leak vectors vs mitigations
  matrix, and recommended pre-mainnet testing checklist.
- Extended `LEVIN_PROTOCOL.md` wire inventory with per-command PQC size
  impact, anonymity sensitivity ratings, and a summary table covering all
  P2P and Cryptonote protocol commands.
- Added privacy considerations section to `STAKER_REWARD_DISBURSEMENT.md`
  covering claim timing, amount correlation, and staked output visibility.
- Added reward-driven privacy/mixing research appendix to
  `DESIGN_CONCEPTS.md` evaluating random maturation delay, claim batching,
  and reward output shaping with adversarial analysis and go/no-go criteria.

### C++17 and Boost migration

- **C++17 standard bump**: `CMAKE_CXX_STANDARD` changed from 14 to 17 in both
  the main `CMakeLists.txt` and the macOS cross-compilation toolchain
  (`contrib/depends/toolchain.cmake.in`). This unblocks `std::filesystem`,
  `std::optional`, and other modern C++ features. Upstream Monero cherry-picks
  that required C++14-to-C++17 back-ports now compile without shims.
- **`boost::optional` → `std::optional` (complete)**:
  Migrated ~486 use sites across ~93 files in `src/`, `contrib/epee/`, and
  `tests/`. Replaced `boost::optional<T>` with `std::optional<T>`,
  `boost::none` with `std::nullopt`, `boost::make_optional` with
  `std::make_optional`, and `.get()` accessor calls with `*` / `->`.
  Added a `std::optional` Boost.Serialization adapter in
  `cryptonote_boost_serialization.h` so PQC auth fields serialize correctly.
  Replaced `BOOST_STATIC_ASSERT`/`boost::is_base_of` with
  `static_assert`/`std::is_base_of` in Trezor `messages_map.hpp`.
- **`boost::filesystem` → `std::filesystem` (wallet/RPC layer)**:
  Migrated `wallet_manager.cpp`, `wallet_rpc_server.cpp`,
  `core_rpc_server.cpp`, and `wallet_args.cpp` from `boost::filesystem` to
  `std::filesystem`. Combined with the earlier utility-file migration, this
  covers all filesystem usage outside of `net_ssl.cpp` (epee, deferred due to
  permissions API coupling).
- **`boost::format` removal (wallet/RPC layer)**:
  Replaced all `boost::format` calls in `wallet2.cpp` (4), `wallet_rpc_server.cpp`
  (8), and `wallet_args.cpp` (1) with stream output or string concatenation.
  `simplewallet.cpp` (106 uses, i18n-sensitive) remains deferred.
- **`boost::chrono`/`boost::this_thread` in daemonizer**: Replaced with
  `std::chrono`/`std::this_thread` in `windows_service.cpp` (PR #9544 equivalent).
- **Medium-effort Boost removals (completed earlier)**:
  - `boost::algorithm::string` (trim, to_lower, iequals, join) replaced with
    `tools::string_util` helpers in `src/common/string_util.h`.
  - `boost::format` replaced with `snprintf`, stream output, or string
    concatenation in `util.cpp`, `message_store.cpp`, `gen_ssl_cert.cpp`,
    `gen_multisig.cpp`.
  - `boost::regex` replaced with `std::regex` in `simplewallet.cpp` and
    `wallet_manager.cpp`.
  - `boost::mutex`, `boost::lock_guard`, `boost::unique_lock`, and
    `boost::condition_variable` replaced with `std::mutex`, `std::lock_guard`,
    `std::unique_lock`, and `std::condition_variable` in `util.h`, `util.cpp`,
    `threadpool.h`, `threadpool.cpp`, and `rpc_payment.h`/`rpc_payment.cpp`.
  - `boost::thread::hardware_concurrency()` replaced with
    `std::thread::hardware_concurrency()`.
- **Filesystem migration (utility files, completed earlier)**:
  - `boost::filesystem` replaced with `std::filesystem` in
    `blockchain_export.cpp`, `blockchain_import.cpp`, `cn_deserialize.cpp`,
    `util.cpp`, `bootstrap_file.h`/`.cpp`, and `blocksdat_file.h`/`.cpp`.
  - Eliminated `BOOST_VERSION` preprocessor conditional in `copy_file()`.
- **Upstream Monero cherry-pick verification**: Confirmed PRs #9628 (ASIO
  `io_service` → `io_context`), #6690 (serialization overhaul), and #9544
  (daemonizer chrono/thread) are already absorbed in our tree.
- **`boost::variant` → `std::variant` (complete)**:
  Full migration from `boost::variant` to C++17 `std::variant` across the
  entire codebase (~100+ replacements in ~40 files):
  - **Serialization layer rewrite** (`serialization/variant.h`): Replaced
    Boost.MPL type-list iteration with C++17 `if constexpr` recursion for
    deserialization and `std::visit` lambda for serialization. Removed all
    `boost::mpl`, `boost::static_visitor`, and `boost::apply_visitor` usage.
  - **Archive headers**: Replaced `boost::mpl::bool_<B>` with
    `std::bool_constant<B>` in `binary_archive.h`, `json_archive.h`, and
    `serialization.h`. Replaced `boost::true_type`/`false_type` and
    `boost::is_integral` with `std` equivalents.
  - **Core typedefs**: Changed `txin_v`, `txout_target_v`, `tx_extra_field`,
    `transfer_view::block`, and Trezor `rsig_v` from `boost::variant` to
    `std::variant`.
  - **Boost.Serialization shim**: Added a local ~45-line `std::variant`
    serialization adapter in `cryptonote_boost_serialization.h` (save/load
    with index + payload, wire-compatible with old `boost::variant` format).
    Removed dependency on `<boost/serialization/variant.hpp>`.
  - **Mechanical replacements** across all `src/` and `tests/` files:
    `boost::get<T>(v)` → `std::get<T>(v)`,
    `boost::get<T>(&v)` → `std::get_if<T>(&v)`,
    `v.type() == typeid(T)` → `std::holds_alternative<T>(v)`,
    `v.which()` → `v.index()`,
    `boost::apply_visitor(vis, v)` → `std::visit(vis, v)`.
  - **P2P layer**: Updated `net_peerlist_boost_serialization.h` to use
    `std::false_type`/`std::true_type` instead of `boost::mpl` equivalents.
  - `tests/unit_tests/net.cpp` retains `boost::get<N>` for `boost::tuple`
    access via `boost::combine` (not variant-related).
- **Remaining deferred Boost areas**: ASIO deep plumbing,
  multi-index containers, Spirit parser, multiprecision, `net_ssl.cpp` filesystem,
  `simplewallet.cpp` format strings, `boost::thread::attributes` (stack size).
  Tagged with `TODO(shekyl-v4)` in source. See `DOCUMENTATION_TODOS_AND_PQC.md`
  section 1.11 for the full backlog.

### CI/CD and build system

- **Boost minimum bumped to 1.74**: `BOOST_MIN_VER` in `CMakeLists.txt` raised
  from 1.62 to 1.74. The `contrib/depends` system now pins Boost 1.74.0
  (previously 1.69.0) and builds with `-std=c++17`. Removed legacy Boost 1.64
  patches (`fix_aroptions.patch`, `fix_arm_arch.patch`) that do not apply to 1.74.
- **CI containers updated to Ubuntu 22.04 minimum**: Dropped Debian 11 and
  Ubuntu 20.04 build jobs from `build.yml`, `depends.yml`, and
  `release-tagged.yml`. Ubuntu 22.04 is now the lowest-common-denominator Linux
  build environment (ships Boost 1.74+ and GCC 11+). Added Ubuntu 24.04 build
  matrix entry.
- Migrated version identifiers from legacy `MONERO_*` symbols to canonical
  `SHEKYL_*` names (`SHEKYL_VERSION`, `SHEKYL_VERSION_TAG`,
  `SHEKYL_RELEASE_NAME`, `SHEKYL_VERSION_FULL`, `SHEKYL_VERSION_IS_RELEASE`)
  in `src/version.h` and `src/version.cpp.in`. The old `MONERO_*` names are
  retained as preprocessor aliases so existing call sites and future Monero
  upstream cherry-picks continue to compile unchanged. The aliases will be
  removed in a single cleanup after v4 RingPQC stabilises.
- Fixed Gitian deterministic build pipeline: replaced all hardcoded Monero
  repository URLs and internal package names with Shekyl equivalents across
  `gitian-build.py`, all 5 gitian descriptor YAMLs, `dockrun.sh`, and the
  `gitian.yml` GitHub Actions workflow. The workflow now passes `--url` to
  ensure the correct repository is cloned. Added checkout error handling with
  an actionable message when a tag/branch is missing.
- Tag-driven versioning: `GitVersion.cmake` now extracts the version string
  from git tags (e.g. `v3.0.2-RC1` → `3.0.2-RC1`). The hardcoded version in
  `version.cpp.in` is replaced with the CMake-substituted `@SHEKYL_VERSION@`;
  a default (`3.1.0`) is used for development builds not on a tag.
  `Version.cmake` centralises the fallback default in `SHEKYL_VERSION_DEFAULT`.
- Updated RPC version string validator (`rpc_version_str.cpp`) from Monero's
  four-number format to Shekyl's three-number semver with optional pre-release
  suffix (e.g. `3.0.2-RC1-release`).
- Updated gitian descriptor names from Monero's `0.18` to Shekyl `3` series.
- Added `release/tagged` GitHub Actions workflow: builds static Linux x86_64
  binaries, cross-compiles Windows x64 via MinGW, and produces `.tar.gz`,
  `.deb`, `.rpm`, `.zip`, and NSIS `.exe` installer artifacts on every `v*` tag.
- Added `BuildRust.cmake` cross-compilation support: detects `CMAKE_SYSTEM_NAME`
  and `CMAKE_SYSTEM_PROCESSOR` to derive Rust target triples for Windows, macOS,
  Android, FreeBSD, and Linux cross-targets (ARM, aarch64, i686, RISC-V);
  automatically configures the MinGW linker for Windows cross-compilation.
- Added Rust toolchain installation to all CI workflows (`build.yml`,
  `depends.yml`, `release-tagged.yml`) and all 5 Gitian deterministic build
  descriptors with appropriate cross-compilation targets; required for
  `libshekyl_ffi.a` linking.
- Fixed Gitian `gitian-build.py` to fetch tags explicitly (`--tags`) during
  repository setup, preventing checkout failures for tag-based builds.
- Enhanced `gitian-build.py` error handling: robust `lsb_release` detection,
  auto-correction of stale clone origins when `--url` changes, and detailed
  diagnostics on checkout failure (lists available remote tags and suggests
  the push command).
- Added `workflow_dispatch` trigger to `gitian.yml` with configurable `tag` and
  `repo_url` inputs, allowing manual re-runs and testing against forks without
  retagging.
- Fixed Doxygen project name from `Monero` to `Shekyl` in `cmake/Doxyfile.in`.
- Replaced bundled Google Test 1.7.0 (2013) with CMake `FetchContent` for
  GoogleTest v1.16.0. Fixes `GTEST_SKIP` compilation errors on all platforms
  without a system gtest. Removes 34k lines of vendored source.
- Upgraded all GitHub Actions workflows to Node.js 24: bumped `actions/checkout`
  to v5, `actions/cache` to v5, `actions/upload-artifact` to v6, and
  `actions/download-artifact` to v7 to resolve the Node.js 20 deprecation
  warnings.
- Trimmed `depends.yml` cross-compilation matrix: dropped i686 Win and i686
  Linux (32-bit targets are dead); deferred RISCV 64-bit and ARM v7 until
  user demand materialises. Active matrix is now ARM v8, Win64, x86_64 Linux,
  Cross-Mac x86_64, Cross-Mac aarch64, and x86_64 FreeBSD (6 targets, down
  from 10). Added Cross-Mac aarch64 to the artifact upload filter.
- Added Linux packaging files: `contrib/packaging/linux/shekyld.service`
  (systemd unit) and `contrib/packaging/windows/shekyl.nsi` (NSIS installer).

### Upstream Monero sync (March 2026)

Cherry-picked 62 upstream Monero commits (from `monero-project/monero` master)
across five risk-phased integration rounds. Key improvements absorbed:

- **Wallet**: Fee priority refactoring (`fee_priority` enum + utility functions),
  improved subaddress lookahead logic, `set_subaddress_lookahead` RPC endpoint
  (no longer requires password), incoming transfers without daemon connection,
  HTTP body size limit, fast refresh checkpoint fix, ring index sanity checks,
  `find_and_save_rings()` deprecation, pool spend identification during scan.
- **Daemon/RPC**: Dynamic `print_connections` column width, ZMQ IPv6 support,
  dynamic base fee estimates via ZMQ, `getblocks.bin` start height validation,
  CryptoNight v1 error reporting, batch key image existence check, blockchain
  prune DB version handling, removed `COMMAND_RPC_SUBMIT_RAW_TX` (light wallet
  deprecated).
- **P2P/Network**: Removed `state_idle` connection state, fixed inverted peerlist
  ternary, removed `#pragma pack` from protocol defs, connection patches for
  reliability, dynamic block sync span limits.
- **Crypto/Serialization**: Fixed invalid `constexpr` on hash functions, added
  `hash_combine.h`, aligned container pod-as-blob serialization, fixed
  `apply_permutation()` for `std::vector<bool>`.
- **Build system**: Removed iwyu/MSVC/obsolete CMake targets, added
  `MANUAL_SUBMODULES` cache option, Trezor protobuf 30 compatibility, fixed
  `FetchContent`/`ExternalProject` cmake usage.
- **Tests**: New unit tests for format utils, threadpool, varint, logging,
  serialization static asserts, cold signing functional test fixes.
- **Misc**: Boost ASIO 1.87+ compatibility, fixed Trezor temporary binding,
  fixed multisig key exchange intermediate message update, `constexpr`
  `cn_variant1_check`, extra nonce length fix, removed redundant BP consensus rule.

Skipped commits (deferred to future integration): input verification caching
(conflicts with `txin_stake_claim`/PQC), `wallet_keys_unlocker` refactoring,
`get_txids_loose` DB API (missing prerequisite), complex subaddress lookahead
fixes, and several CMake/depends version bumps that conflict with Shekyl's
build system divergences.

Cherry-picked code was initially adapted to C++14 compatibility; with the
subsequent C++17 standard bump, many of those back-ports are now unnecessary
and can use native `std::optional`, `std::string_view`, etc.

### Documentation

- Added `docs/EXECUTABLES.md`: comprehensive reference for all 17 build
  artifacts covering usage, CLI options, interactive commands, and examples
  for `shekyld`, `shekyl-wallet-cli`, `shekyl-wallet-rpc`, blockchain
  utilities, and debug tools.

### Operations

- Added `utils/systemd/shekyld.service` for Shekyl-native daemon service
  deployment (`/usr/local/bin/shekyld` + `/etc/shekyl/shekyld.conf`).
- Updated `docs/INSTALLATION_GUIDE.md` related-doc references to include seed
  operations documentation in the companion `shekyl-dev` docs set.
- Added `docs/BLOCKCHAIN_NETWORKS.md` with a deep-dive comparison of network
  models across Bitcoin, Ethereum, Monero, Solana, Polkadot, and Avalanche,
  and mapped those patterns to Shekyl's mainnet/testnet/stagenet/fakechain
  usage guidance.
- Migrated Shekyl stagenet defaults from legacy Monero ports to
  `13021` (P2P), `13029` (RPC), and `13025` (ZMQ), and aligned test/docs
  references so `--testnet` workflows use `12029` while scripts support
  overrideable network/daemon variables.
- Updated libwallet API helper scripts to call `shekyl-wallet-cli` (not
  `monero-wallet-cli`) so test tooling matches Shekyl binary names.

### Staking (end-to-end claim-based system)

- Added `txout_to_staked_key` output target type for locking coins at a chosen
  tier (short/medium/long). Outputs carry `lock_tier` and `lock_until` fields
  enforced at the consensus layer.
- Added `txin_stake_claim` input type for claiming accrued staking rewards.
  Claims specify a height range and are validated against deterministic per-block
  accrual records.
- Extended LMDB schema with `staker_accrual` and `staker_claims` tables plus a
  `staker_pool_balance` property for on-chain reward pool accounting.
- Per-block accrual logic computes staker emission share and fee pool allocation
  at block insertion time, with full reversal on reorg (block pop).
- Consensus validation: `lock_until` enforcement on staked outputs, claim amount
  verification against accrual records, watermark-based anti-double-claim,
  maximum claim range (10,000 blocks), pool balance sufficiency checks.
- Pure claim transactions (`txin_stake_claim`-only inputs) use `RCTTypeNull`
  signatures, cleanly separated from ring-signature transaction validation.
- Extended `tx_destination_entry` with `is_staking`, `stake_tier`, and
  `stake_lock_until` fields. `construct_tx_with_tx_key` emits
  `txout_to_staked_key` outputs when `is_staking` is set.
- Extended `transfer_details` with `m_staked`, `m_stake_tier`, and
  `m_stake_lock_until` for wallet-side staking metadata tracking.
- Implemented wallet2 methods: `create_staking_transaction`,
  `create_unstake_transaction`, `create_claim_transaction`,
  `get_matured_staked_outputs`, `get_locked_staked_outputs`,
  `get_claimable_staked_outputs`, `get_staked_balance`,
  `estimate_claimable_reward`.
- Added simplewallet commands: `stake <tier> <amount>`, `unstake`,
  `claim_rewards`.
- Added wallet RPC endpoints: `stake`, `unstake`, `get_staked_outputs`,
  `claim_rewards`.
- Added daemon RPC endpoint: `get_staking_info` returning current staking
  metrics (height, stake ratio, pool balance, emission share, tier lock blocks).
- Wired `stake_ratio` and `staker_pool_balance` in `/get_info` to live
  blockchain state.
- No minimum stake amount enforced (matches design doc).
- Fixed compilation errors from `txin_stake_claim` missing in exhaustive
  `boost::static_visitor` patterns: added `operator()` overloads to the
  double-spend visitor (`blockchain.cpp`) and the JSON serialization visitor
  (`json_object.cpp`), added JSON deserialization branch for `"stake_claim"`
  inputs, added `toJsonValue`/`fromJsonValue` declarations and implementations
  for `txin_stake_claim`, and added Boost.Serialization `serialize()` free
  function for wallet binary archive support (`cryptonote_boost_serialization.h`).

### Consensus and mining economics

- Wired Four-Component economics to live chain-state inputs for miner reward
  paths:
  - block template construction now passes rolling `tx_volume_avg`,
    `circulating_supply`, and `stake_ratio` to `construct_miner_tx`
  - miner transaction validation now uses the release-multiplier reward path
    and non-placeholder fee-burn inputs
  - tx pool block template estimation now uses the same rolling
    `tx_volume_avg` reward path for consistency
- Added `Blockchain::get_tx_volume_avg(height)` and
  `Blockchain::get_stake_ratio(height)` (stubbed to `0` until staking state is
  consensus-tracked).

### Modular PoW

- Added pluggable PoW schema abstractions:
  - `IPowSchema` interface
  - `RandomX` and `Cryptonight` schema implementations
  - PoW registry-based selection preserving existing behavior by block version
- Refactored `get_block_longhash` to route through the PoW schema registry while
  keeping existing RandomX seed handling and the historical block 202612
  workaround.
- Updated miner thread preparation to call schema-level
  `prepare_miner_thread(...)` (RandomX prepares thread context; Cryptonight is
  a no-op).
