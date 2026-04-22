# Resolved items — sweep of 2026-04-19

Historical record of items closed in `docs/FOLLOWUPS.md` and
`docs/STRUCTURAL_TODO.md`. Git history is the authoritative archive of the
code changes themselves; this file preserves the "what was fixed and why"
narrative that previously lived inline in the tracking documents, so the
reasoning doesn't require archaeology to recover.

Entries are grouped by source document. Section headings mirror the
headings that existed in the source documents at the time of the sweep.

---

# From `docs/STRUCTURAL_TODO.md`

## Platform Abstraction Gaps

### `ssize_t` not centralized
Created `src/common/compat.h` with the centralized `ssize_t` typedef for
MSVC. Both `util.h` and `download.h` `#include "common/compat.h"` instead
of inline guards. *(Landed on `dev` in `f275a6a3b`; merged to
`feature/msvc-wallet-core` in `93440c429`.)*

### Unconditional POSIX includes scattered across 6+ files
`unistd.h`, `dlfcn.h`, `sys/mman.h` were individually guarded with
`#ifndef _WIN32` or `#if !defined(_MSC_VER)` in eight first-party files
(`util.cpp`, `stack_trace.cpp`, `slow-hash.c`, `rx-slow-hash.c`,
`aligned.c`, `spawn.cpp`, `keccak.c`, `CryptonightR_JIT.c`). All eight
sites now `#include "common/compat.h"`, which owns the three POSIX vs.
Windows header blocks in one place. A CI lint step
(`.github/workflows/build.yml`, modeled on the `BOOST_FOREACH` guard)
rejects new direct `#include <unistd.h|dlfcn.h|sys/mman.h>` in `src/`
outside a tight allow-list (OS-specific arms in `miner.cpp` /
`password.cpp`, vendored ref10 / oaes code, the arch-specific inner
`sys/mman.h` blocks in `slow-hash.c`, and `compat.h` itself). The
behavioral shims still inlined in `util.cpp` (`setenv`→`putenv`,
`umask`→noop, `closefrom`→noop) are a separate concern, tracked as a
V3.2 item in `docs/FOLLOWUPS.md` — they define *what a function does*
on Windows, not *which header supplies a symbol*. *(Landed on `dev` in
`613b14e55`, April 2026.)*

### `xor` used as a C parameter name in `slow-hash.c`
Renamed to `xor_pad` in both x86/SSE and ARM/NEON variants of
`aes_pseudo_round_xor()`. *(Landed on `feature/msvc-wallet-core` in
`bb5763742`.)*

## Language Standard Drift

### C++20 designated initializers in a C++17 codebase
All 10 call sites across 6 files (`blockchain.cpp`, `cryptonote_core.cpp`,
`levin_notify.cpp`, `multisig_tx_builder_ringct.cpp`, `wallet2.cpp`)
rewritten from `{.field = val}` to C++17 member assignment. *(Landed on
`dev` in `f275a6a3b`; merged to `feature/msvc-wallet-core` in
`93440c429`.)* Audit for other C++20-isms (concepts, ranges,
`std::format`, coroutines, `<=>` operator) completed April 2026: none
found in `src/`.

### MSVC treats `xor` as reserved in C mode
Even after moving `/FIiso646.h` to C++ only, MSVC rejects `xor` as a
parameter name in C files. MSVC appears to reserve C++ alternative tokens
even in C mode. The `slow-hash.c` parameter was renamed to `xor_pad` in
both x86/SSE and ARM/NEON variants. *(Landed on `feature/msvc-wallet-core`
in `bb5763742`.)* Any future C code using `xor`, `and`, `or`, etc. as
identifiers should avoid these names.

### `__thread` TLS qualifier not portable
Replaced `__thread` with standard `thread_local` (C++11) in all three
files: `easylogging++.cc` *(landed on `dev` in `f275a6a3b`)*, and
`perf_timer.cpp` + `threadpool.cpp` *(landed on `dev` in `17fb55648`;
originally on `feature/msvc-wallet-core` in `5dcef4bdc`)*.

### MSVC iterator types are classes, not raw pointers
`boost::as_literal()` returns iterators that are classes on MSVC
(`std::_Array_const_iterator`), not raw `const char*`. Code that
`reinterpret_cast`s iterators to pointers breaks. Fixed in epee's HTTP
auth code by casting through `&*it` (dereference then address-of) to
obtain a raw pointer portably. *(Landed on `feature/msvc-wallet-core` in
`d92533e34`.)* Other similar patterns may exist in epee.

### `unbound.h` include not guarded in `util.cpp`
The `#include "unbound.h"` and `unbound_built_with_threads()` function
body/call site were not wrapped in `HAVE_DNS_UNBOUND`. Added
`#ifdef HAVE_DNS_UNBOUND` guards around the include and all call sites in
`util.cpp`. *(Landed on `feature/msvc-wallet-core` in `bb5763742`.)*

## Dead / Broken Code Discovered

### `throw_wallet_ex` MSVC Boost.PP fallback was broken for years
Removed the dead Boost.PP overload-generation code path and unified on the
variadic template version with `/Zc:preprocessor` for conformant macro
expansion. *(Landed on `feature/msvc-wallet-core` in `feda06508`.)*
**Lesson:** MSVC-specific code paths need CI coverage to avoid bit-rot.

### `portable_storage` overly strict `static_assert`s
Removed the three overly strict `static_assert`s and changed
`portable_storage_base.h` from rvalue-ref to pass-by-value parameters.
*(Landed on both `dev` in `c10368e9d` and `feature/msvc-wallet-core` in
`8a4a6c29f`.)* Remaining thought: consider explicit template
instantiation tests for the serialization layer to catch deduction issues
across compilers.

## Third-Party / Dependency Issues

### easylogging++ vendored with no MSVC support
`external/easylogging++/easylogging++.cc` had three issues, all fixed:
unconditional `#include <unistd.h>` (guarded in `d92533e34`), `__thread`
TLS (replaced with `thread_local` in `f275a6a3b`), and hardcoded `-fPIC`
in CMakeLists.txt (replaced with `POSITION_INDEPENDENT_CODE ON` in
`0730a7bd4`). All three fixes confirmed in tree April 2026. The library
is unmaintained upstream; any future MSVC issues will require local
patches. The open question of whether to replace the library wholesale
with `spdlog` or similar is tracked separately in `docs/FOLLOWUPS.md`.

**Superseded by the full easylogging++ retirement below
(V3.x alpha.0 / Chore #2).** The local-patches tradeoff never had
to be exercised: the vendored tree was removed wholesale in
commit `ded9875b6` and the cross-platform burden now lives on the
Rust subscriber instead of on a dead upstream.

### Replace easylogging++ with a maintained logger (Chore #1 + Chore #2)
Two-chore retirement of the unmaintained vendored `easylogging++`
tree in favor of the Rust `shekyl-logging` crate (`tracing` +
`tracing-subscriber` + `tracing-appender`). Both chores have
landed:

- **Chore #1 (V3.1 alpha.4)** — Rust-side consolidation. The
  `rust/shekyl-logging` crate was introduced, every Rust binary
  (`shekyl-cli`, `shekyl-wallet-rpc`, `shekyl-daemon-rpc`) was
  migrated to a shared init path under the `SHEKYL_LOG` env var,
  and a translator for the legacy easylogging++ category grammar
  (`net.p2p:DEBUG,wallet.wallet2:INFO`, numeric `0..=4` presets,
  `+`/`-` modifiers) was shipped so Chore #2 could reuse a single
  filter engine. Landed on `chore/rust-logging-consolidation`,
  merged to `dev` in `aefcfb365`.

- **Chore #2 (V3.x alpha.0)** — C++ shim + vendor retirement.
  `contrib/epee/include/misc_log_ex.h` now routes every `MINFO` /
  `MDEBUG` / `MWARNING` / `MCINFO` / etc. call through the
  `shekyl_log_emit` / `shekyl_log_level_enabled` FFI declared in
  `src/shekyl/shekyl_log.h` (landed on
  `chore/cxx-logging-consolidation` in `a617ec676`;
  `contrib/epee/src/mlog.cpp` was rewritten over the same FFI in
  `0aa8e3919`). The vendored `external/easylogging++/` tree was
  deleted in `ded9875b6`. `MONERO_LOGS` and `MONERO_LOG_FORMAT`
  were retired from every in-tree consumer in `4ff1acc5b` + the
  V3.x alpha.0 CHANGELOG entry; `SHEKYL_LOG` is now the single
  operator-facing knob. The C++ `el::` namespace survives as a
  thin typedef-only shim in `misc_log_ex.h` so the ~1,345
  existing call sites keep compiling without churn; no production
  code touches `el::Logger` / `el::Configurations` any more. The
  `shekyld` default file sink resolves to `~/.shekyl/logs/shekyld.log`
  (suffixed `-testnet` / `-stagenet` / `-regtest` for alternate
  networks) with POSIX `0600` perms and 100 MB × 50-file rotation,
  enforced unconditionally by the Rust side.

**Known V3.x alpha.0 regressions (intentional, scope-contained).**

- Output format is not byte-compatible with the prior
  easylogging++ layout. RFC 3339 UTC timestamps, full-word level
  tokens, structured target strings. Documented in the V3.x
  alpha.0 `docs/CHANGELOG.md` entry and in
  `docs/USER_GUIDE.md` §"Logging".
- `MLOG_SET_THREAD_NAME(...)` is a no-op. Call sites in
  `abstract_tcp_server2.inl`, `miner.cpp`, `download.cpp` still
  compile and pass their argument, but the `[SRV_MAIN]` /
  `[miner 3]` / `DL12` labels no longer reach the log stream.
  Restoring semantic labels via `pthread_setname_np` or
  equivalent is a V3.2 follow-up tracked in
  `docs/FOLLOWUPS.md`.

**Unit-test coverage.** `tests/unit_tests/logging.cpp` was
rewritten from driving `el::Logger` / `el::Configurations`
internals to driving the production macros (`MERROR`, `MWARNING`,
`MINFO`, `MCINFO`) and asserting observable output via a
`dup2`-based stderr-capture fixture. Preserves the legacy
`TEST(logging, no_logs)` parity invariant and adds positive
controls for level thresholds, category routing, and concurrent
emission.

### `boost::iterator_range` constructor regression with Boost 1.90
`http_auth.cpp` used `boost::iterator_range<const char*>` with
`boost::as_literal()`, which returns a different iterator type in Boost
1.90 on MSVC. Fixed by switching to `auto` deduction so the type adapts
to whatever `boost::as_literal()` returns. *(Landed on
`feature/msvc-wallet-core` in `d92533e34`.)* Watch for similar Boost 1.90
regressions in other epee / Monero-inherited code — this was an early
signal of a class of problems.

## CI / Build Hygiene

### No CI guard against `BOOST_FOREACH` re-introduction
31 `BOOST_FOREACH` / `BOOST_REVERSE_FOREACH` sites were manually replaced
with range-based for loops *(cherry-picked to `dev` in `591e3b5ee` and
`ee8ea9719`; originally on `feature/msvc-wallet-core` in `7eb61302b` and
`fe5b076a7`)*. CI lint step added to `.github/workflows/build.yml` that
fails if any `BOOST_FOREACH` matches are found. *(Landed in PR-cleanup,
April 2026.)*

### `NOMINMAX` required on MSVC
Added `/DNOMINMAX` to the MSVC `add_definitions` to prevent Windows
`min`/`max` macro collisions with `crypto.h`. *(Cherry-picked to `dev` in
`591e3b5ee`; originally on `feature/msvc-wallet-core` in `7eb61302b`.)*
This is a well-known Windows issue but was never needed before because
MSVC was never tested. If future code includes `<windows.h>` before
`NOMINMAX` is defined, the collision will resurface.

### MSVC Internal Compiler Error on `obj_blocks` and `obj_cncrypto`
Both ICEs are resolved. The `obj_blocks` ICE was caused by
`const unsigned char name[]={};` (empty array initializer) generated from
0-byte `.dat` files; the generator now emits `{0x00}` with `_len = 0`.
The `obj_cncrypto` ICE was caused by `CryptonightR_JIT.c` and its
heavyweight includes (`variant4_random_math.h`, `CryptonightR_template.h`)
overwhelming the PDB type server. A stub (`CryptonightR_JIT_stub.c`)
replaces it on MSVC, providing the same `return -1` without the
problematic headers. The ICE reproduces on both MSVC 14.44 (VS 2022)
and 14.50 (VS 2026) — the stub is the actual fix, not a compiler
upgrade. Full diagnosis in
`shekyl-core/docs/COMPILING_DEBUGGING_TESTING.md`.

### `ARCH_ID` not lowercased, breaking RandomX JIT on MSVC
**Was high priority** — silent performance degradation on MSVC daemon.

Root `CMakeLists.txt` set `ARCH_ID` from `CMAKE_SYSTEM_PROCESSOR`
without lowercasing. On Windows, `CMAKE_SYSTEM_PROCESSOR` returns
`AMD64` (uppercase). RandomX's `CMakeLists.txt` checks for lowercase
`"amd64"` to include `jit_compiler_x86.cpp`. RandomX's own CMakeLists
lowercases when `ARCH_ID` isn't already set, but the parent scope
pre-empts that. Result: `jit_compiler_x86.cpp` was never compiled,
causing LNK2019 for `JitCompilerX86` symbols. MSVC-built `shekyld`
would have run RandomX in interpreted mode only (orders of magnitude
slower for mining). Fix: `string(TOLOWER "${ARCH_ID}" ARCH_ID)` in root
CMakeLists. *(Landed on `dev` in `feb631d08`, April 2026.)*

### `blocks.cpp` C/C++ linkage mismatch on MSVC
**Was medium priority** — daemon link failure on MSVC only.

`blocks.cpp` declared `extern const unsigned char checkpoints[]` etc.
without `extern "C"`. The generated `.c` files produce C-linkage
symbols. On GCC/Clang, namespace-scope variables don't get C++
name-mangled, so C and C++ symbols match. On MSVC, they're mangled
differently (`?checkpoints@@3QBEB` vs `_checkpoints`), causing LNK2019.
Fix: wrapped extern declarations in `extern "C" {}`. *(Landed on `dev`
in `feb631d08`, April 2026.)*

### `COVERAGE=ON` applies GCC-only flags without MSVC guard
`monero_enable_coverage()` in root `CMakeLists.txt` (line 664) already
guards with `if(NOT MSVC)`. Verified April 2026 (no change needed).

### `enable_stack_trace` linker flag not MSVC-safe
`src/CMakeLists.txt` `enable_stack_trace` function (line 54) already
guards the `-Wl,--wrap=__cxa_throw` flag with `if(STATIC AND NOT MSVC)`.
Verified April 2026 (no change needed).

## Data Type Portability

### `long` is 32-bit on MSVC x64 — several format/parse mismatches
Several sites outside the wallet-core library used `long` for values
that can exceed 32 bits. `simplewallet.cpp` was deleted from the
repository. `bootstrap_file.cpp` now uses `std::streamoff` end-to-end
for stream positions (verified April 2026). No remaining `long`-typed
stream positions or `%lu`-formatted `uint64_t` values found in active
code.

### `blockchain_import.cpp` uses POSIX `sleep()`
Replaced `sleep(90)` with
`std::this_thread::sleep_for(std::chrono::seconds(90))` in
`blockchain_import.cpp`. *(Landed on `feature/msvc-wallet-core` in
`fda82e3d4`.)*

### 32-bit shift widened to 64-bit — 23 sites in consensus code (C4334)
**Was medium priority** — potential UB if shift amount ever reached 32.

Pattern: `1 << n` stored in `uint64_t`. Changed all 23 sites to
`1ULL << n`:

- **`cryptonote_format_utils.cpp`** — 3 sites in tx format parsing
- **`bulletproofs.cc`** — 6 sites in range proofs
- **`bulletproofs_plus.cc`** — 6 sites in range proofs
- **`rctTypes.cpp`** — 5 sites in RingCT types (3 in `d2h`, 2 in `d2b`)
- **`rctSigs.cpp`** — 2 sites in RingCT signatures
- **`multiexp.cc`** — 2 sites in multi-exponentiation
- **`wallet2.cpp`** — audited, already used `(uint64_t)1`

*(Fixed on `dev` branch, April 2026.)*

### Right shift by too-large amount — data loss (C4333)
**Was medium priority** — actual data loss on MSVC.

- **`src/common/util.cpp`** — Changed `wint_t cp` to `uint32_t cp` in
  `get_string_prefix_by_width()`. On MSVC, `wint_t` is 16-bit
  `unsigned short`, so `cp >> 18` shifted by more than the type width.
- **`src/common/utf8.h`** — Added `static_cast<uint32_t>` on the
  transform result in `utf8canonical()` to ensure proper type widening.

*(Fixed on `dev` branch, April 2026.)*

### Unsafe bool/char mixing in `wallet2.h:2324` (C4805)
Line/pattern no longer exists after wallet refactoring (`wallet2.h` is
now 2144 lines; `|=` bool/char pattern not found).

### Unsigned negation in `wallet2.cpp:772` (was 782) (C4146)
The `std::advance(left, -N)` call at line 772 already uses
`-static_cast<ptrdiff_t>(N)`, avoiding unsigned negation. Verified
April 2026 (no change needed).

## Unsafe `memcmp` Usage

Audit of all 111 first-party `memcmp` call sites (25 in `src/`, 2 in
`contrib/`, 84 in `tests/`) revealed three classes of problems: a
correctness bug on non-POD structs, timing-unsafe comparisons on secret
material, and inconsistent use of the existing constant-time comparison
infrastructure. All three are now resolved:

### CRITICAL — `memcmp` on `account_public_address` (non-POD struct)
**Was critical** — **broken before fix**, not a theoretical risk.

`account_public_address` contains `std::vector<uint8_t> m_pqc_public_key`.
`memcmp` over such a struct compared vector bookkeeping, not key bytes.

`operator==` / `operator!=` already compared `m_spend_public_key`,
`m_view_public_key`, and `m_pqc_public_key` member-wise in
`cryptonote_basic.h`. All production `memcmp` sites on
`account_public_address` (`wallet2.cpp`, `wallet2_ffi.cpp`,
`wallet_rpc_server.cpp`, `unsigned_transaction.cpp`) now use `==` /
`!=`. (`simplewallet.cpp` was deleted from the repository.) Added
`static_assert(!std::is_trivially_copyable_v<account_public_address>)`
after the struct to discourage future raw `memcmp` on the type.

### MEDIUM — `memcmp` on secret / HMAC material (timing attack risk)
**Was medium priority** — local-access timing side channels.

`wallet2::is_deterministic` now uses `crypto_verify_32` for the
view-secret check. Ledger `HMACmap::find_mac` uses `crypto_verify_32`
for secret lookup. Both replace short-circuiting `memcmp` on 32-byte
secrets.

### LOW — Inconsistent constant-time macro usage in `generic-ops.h`
**Was low priority** — no current vulnerability, but a footgun.

All 32-byte types (`public_key`, `key_image`, `hash`) now use
`CRYPTO_MAKE_HASHABLE_CONSTANT_TIME` → `crypto_verify_32`. The
non-constant-time `CRYPTO_MAKE_COMPARABLE` is retained only for
non-32-byte types (`signature` at 64 bytes, `view_tag` at 1 byte,
`hash8` at 8 bytes) where `crypto_verify_32` does not apply. This
eliminates the footgun of choosing the wrong macro for new 32-byte
types.

### Additional `memcmp` notes (safe, audited)

- `tx_pool.cpp:1656` — `memcmp(&original_meta, &meta, sizeof(meta))`:
  `static_assert` added to enforce trivially-copyable layout and
  192-byte struct size. All padding and new fields
  (`fcmp_verification_hash`, `fcmp_verified`) are zero-initialized at
  every meta construction site in `add_tx`.
- `wallet2.cpp:13170,14260` — file magic comparisons: byte-array
  literals, no issues.
- `wallet2.cpp:10834` — `std::memcmp` on raw `data()` of public key
  blob at a computed offset: correct for fixed-size byte arrays.
- `crypto.cpp:335`, `rx-slow-hash.c:75-76` — byte-array comparisons
  against constants: no issues.
- ~90 test-only `memcmp` calls: low priority, but `tests/` should adopt
  `operator==` as production code is migrated.

## Daemon Orchestration Layer

Resolved in V3.1 (`chore/remove-daemonizer-layer`, April 2026). The
refactor collapsed `src/daemon/`'s four wrapper classes and the
`t_executor` shim into a single `daemonize::Daemon` in
`daemon.{h,cpp}`, deleted `src/daemonizer/` wholesale, and moved the
Windows admin-vs-user default data-directory logic into
`src/common/daemon_default_data_dir.{h,cpp}` (pinned by a
`daemon_default_data_dir` unit test). `shekyl-wallet-rpc` received the
same treatment: its inline class was renamed to `WalletRpcDaemon` and
its `daemonizer::init_options` / `daemonizer::daemonize` calls were
replaced by a direct `WalletRpcDaemon{vm}.run()`. A small transitional
shim (`src/common/removed_flags.{h,cpp}`, `TODO(v3.2)`) prints a
migration message for `--detach`, `--pidfile`, and the Windows
`--*-service` flags. See `CHANGELOG.md` V3.1 entry and `FOLLOWUPS.md`
§"`removed_flags` shim sunset" for the V3.2 deletion plan.

The original analysis (wrapper classes with no abstraction value,
`t_executor` dead abstraction, Windows circular includes,
`boost::program_options` threading) is preserved in git history on the
commit that introduced it; see `docs/STRUCTURAL_TODO.md` prior to
`613b14e55` for the full pre-refactor diagnosis.

## `wallet2_ffi` carried filesystem state

**Was medium priority** — inherited Monero `wallet_rpc_server`
scaffolding leaking host-filesystem assumptions across the FFI
boundary.

`wallet2_handle` held a `std::string wallet_dir`, populated via
`wallet2_ffi_set_wallet_dir(dir)` and concatenated with `"/" + filename`
at the four wallet-file entry points. Safe on POSIX, wrong on Windows:
`"C:\\Users\\x\\...\\AppData" + "/" + "My Wallet.keys"` produced
mixed-separator paths that displayed incorrectly and broke some
Win32-only APIs, while NTFS tolerated enough of them to hide the bug in
alpha.

Resolved April 2026: removed `wallet_dir` from `wallet2_handle` and
deleted `wallet2_ffi_set_wallet_dir`. The four FFI entry points now
take a full `wallet_path` string built by the caller — the GUI wallet
uses Rust's `PathBuf::join`, which is platform-correct on every
target. `validate_filename` narrowed to `validate_wallet_path` (empty
check only); path-component safety is the caller's job now that the
caller owns directory resolution. The legacy C++ `wallet_rpc_server`
keeps its own `wallet_dir` state because it does not route through the
FFI. Per `20-rust-vs-cpp-policy.mdc`: path construction parses
untrusted input and defines a contract other code consumes — the Rust
side is the right owner.

---

# From `docs/FOLLOWUPS.md`

## Test / FFI coverage

### `signing_round_trip.rs` tests Rust proof API, not raw FFI
The test now calls `shekyl_sign_fcmp_transaction` and
`shekyl_fcmp_verify` through C-ABI FFI, exercising the full FFI
boundary serialization for signing. See
`rust/shekyl-ffi/tests/signing_round_trip.rs`.

### 1 unit test skipped: FCMP++ non-coinbase transaction construction
`JsonSerialization.FcmpPlusPlusTransaction` restored using
`make_fcmp_transaction()` which builds a real v3 FCMP++ transaction via
the full Rust FFI signing pipeline: KEM keypair generation, output
construction, scan-and-recover, curve tree leaf+root building, FCMP++
proof signing (`shekyl_sign_fcmp_transaction`), proof verification
(`shekyl_fcmp_verify`), and PQC auth signing (`shekyl_sign_pqc_auth`).
The resulting transaction struct is populated with real cryptographic
data (key images, commitments, proof blobs, PQC public keys and
signatures) and round-tripped through JSON serialization.

### Fuzz harness for `derive_output_secrets`
Added `fuzz_derive_output_secrets` target in
`rust/shekyl-crypto-pq/fuzz/fuzz_targets/`. Asserts determinism,
non-zero `ho`/`y` for all non-empty `combined_ss` inputs, and no panics
on truncated/oversized inputs.

### Witness header round-trip test
Added `witness_header_build_then_parse_roundtrip` test in
`rust/shekyl-ffi/src/lib.rs` with locked vectors in
`docs/test_vectors/WITNESS_HEADER.json`. Verifies all 8 header fields
survive the build → blob → parse cycle byte-for-byte.

### MSVC CI now covers daemon target
The `build-windows-msvc` job builds `--target daemon wallet`. Any new
daemon code must compile under MSVC. If a future change introduces
MSVC-only errors, shekyl-core CI will catch it before the GUI wallet
release workflow does. No further action needed unless the MSVC CI job
is removed or the GUI wallet stops building the daemon target.

## Cryptography / consensus

### Genesis TX blobs use zero-filled `enc_amounts`/`outPk`
The genesis pipeline now consumes Bech32m addresses, derives X25519
from the Ed25519 view key via Edwards→Montgomery mapping, assembles the
full 1216-byte `m_pqc_public_key` (`X25519_pub || ML-KEM_ek`), and
routes through `build_genesis_coinbase_from_destinations` to produce
real commitments and KEM ciphertexts. The `genesis_builder` tool has
been updated; testnet hex regeneration requires a rebuild after this
change. See `scripts/verify_genesis.py` in `shekyl-dev` for
reproducibility verification.

### y=0 consensus check for two-component output keys (infeasible)
A consensus-level rejection of `y=0` outputs is not implementable: the
verifier sees only `O` on the chain and `y` is a secret derived from
the KEM shared secret. Testing whether `O` lies in the G-only subgroup
(i.e., `O = x*G` for some `x` with zero T-component) requires knowing
the discrete log relationship between G and T, which is unknown by
design. Defense is structural: (1) `derive_output_secrets` hard-asserts
`y != 0` (probability 2^-252 from honest HKDF), (2) `construct_output`
is the sole construction path, (3) `fuzz_derive_output_secrets` covers
the derivation with arbitrary inputs.

### scheme_id binding (`expected_scheme_id` unused) — active
Contrary to the original note, `expected_scheme_id` IS used:
`blockchain.cpp` (line 3766) calls `verify_transaction_pqc_auth(tx,
expected_scheme)` where `expected_scheme` is derived from
`tx.pqc_auths[0].scheme_id`. This enforces cross-input scheme
consistency — all inputs in a transaction must use the same
`scheme_id`. The unused one-arg overload was removed (April 2026); the
function now has `expected_scheme_id = boost::none` as a default
parameter. Scheme downgrade protection across outputs is still provided
by the `h_pqc` curve tree leaf commitment as described in
`PQC_MULTISIG.md` Attack 1.

### `on_get_curve_tree_path` RPC reads current tree state, not reference-block state
Fixed by computing `ref_leaf_count` at `reference_height` (subtracting
leaves drained after reference block via
`get_pending_tree_drain_entries`), capping all leaf/layer reads to
`ref_leaf_count`, and applying boundary-chunk hash trimming via
`shekyl_curve_tree_hash_trim_{selene,helios}` for sibling chunks that
grew since the reference block.

### `core_tests` FCMP++ proof verification failures (3 tests)
Root cause: `test_generator::construct_block` set `blk.curve_tree_root`
to `shekyl_curve_tree_selene_hash_init()` (a fixed placeholder), not
the real Merkle root from the DB. FAKECHAIN skipped the root check, so
block headers were stored with placeholder roots. `apply_fcmp_pipeline`
read the placeholder root from the reference block header but assembled
witness paths from the real LMDB tree — causing an inconsistent proof
that verification rejected.

Fix: added per-height curve tree root storage (`m_curve_tree_roots`
LMDB table) that records the real root at every block height. Both the
prover (`apply_fcmp_pipeline`) and verifier (`check_tx_inputs`) now
read the root from this table instead of block headers. Also aligned
`compute_leaf_count_at_height` with production `collect_outputs` logic
(output-type and `outPk` bounds checks).

### Branch layer depth formula correction (April 12, 2026)
`shekyl-tx-builder` validation rule corrected from `c1 + c2 == depth`
to `c1 + c2 + 1 == depth` (commit `03d233652`). Discovered by the FFI
signing round-trip test (Phase 6). Autopsy: old tests used depth=2 with
c1=1, c2=1 — structurally wrong for a depth-2 tree but happened to
satisfy the wrong formula. Two errors cancelled: wrong fixture + wrong
rule = passing test that tests nothing. Depth=1 was never tested
before Phase 6.

Verifier-side check: not needed — `shekyl-fcmp::proof::verify` uses
proof-structure-implicit depth enforcement (branch data embedded in
proof blob; verifier replays transcript using `tree_depth` as layer
count). Both prover and verifier reject depth=0.

Hardening applied:

- `MAX_TREE_DEPTH=24` constant added to `shekyl-fcmp::lib` (single
  source of truth), enforced in both
  `shekyl-tx-builder::validate_inputs` and `shekyl-fcmp::proof::verify`.
- C1/C2 alternation constraint now enforced in `validate_inputs`
  (previously only total count was checked). The `error.rs` doc was
  corrected — it previously stated `c2 == c1 or c2 == c1 + 1` but the
  protocol requires `c1 == c2 or c1 == c2 + 1` (C1 at even indices, C2
  at odd).
- Parametric depth sweep test covers `1..=MAX_TREE_DEPTH` plus
  rejection at `MAX_TREE_DEPTH + 1`.
- All test fixtures in `shekyl-tx-builder/src/tests.rs` corrected to be
  spec-derived (c1/c2 split computed from depth per the tower
  alternation rule, not pasted from observed behavior).
- Testing rule added to `.cursor/rules/40-testing.mdc`: fixtures must
  be spec-derived, not behavior-derived.

### FFI depth-to-layers convention fix (April 15, 2026)
`shekyl_fcmp_prove` and `shekyl_fcmp_verify` were performing an
internal `layers = tree_depth + 1` conversion. This was opaque to C++
callers and led to double-conversion bugs when test code also added 1.
Fix: removed the internal conversion; FFI functions now accept `layers`
directly. C++ callers (`blockchain.cpp`, `rctSigs.cpp`) explicitly
convert before calling. `shekyl_sign_fcmp_transaction` still accepts
LMDB depth and converts internally. Both FFI tests
(`signing_round_trip.rs`, `json_serialization.cpp`) simplified to
layers=1 Selene root with LMDB depth=0. Also caught a transient c1/c2
alternation swap in `validate.rs` introduced during the same
refactoring session.

## PQC multisig V3.1

### FFI returns `bool` not error codes
All three verification FFI functions (`shekyl_pqc_verify`,
`shekyl_pqc_verify_with_group_id`, `shekyl_fcmp_verify`) now return
`u8` error codes: 0 = success, nonzero = typed error discriminant.
PQC verify uses `PqcVerifyError` codes 1-11 (from
`shekyl-crypto-pq/src/error.rs`). FCMP verify uses `VerifyError`
discriminants 1-7 (from `shekyl-fcmp/src/proof.rs`). The debug-only
`shekyl_pqc_verify_debug` is deleted (now redundant). C++ callers
(`tx_pqc_verify.cpp`, `blockchain.cpp`) log error codes in all build
modes. Per `30-ffi-discipline.mdc`.

### Harden ephemeral seed stack copies in `construct_multisig_output_for_sender`
`ed_seed` and `ml_seed` in `multisig_receiving.rs` are now
`Zeroizing<[u8; 32]>`, ensuring automatic zeroization on drop. Closes
the theoretical side-channel surface identified during the V3.1 audit
response review.

## Dependencies / supply chain

### `rpassword` transitive dependency audit (covered by CI)
`rpassword = "7"` is pinned in `shekyl-cli/Cargo.toml` (resolves to
7.4.0). `cargo audit` runs in CI (`.github/workflows/build.yml` lines
429-431) and covers `rpassword` and its `windows-sys` transitive
dependency. `rust/audit.toml` acknowledges known non-applicable
advisories. No additional audit tooling needed.

## Documentation

### `docs/AUDIT_SCOPE.md` not yet created
`docs/AUDIT_SCOPE.md` created (April 12, 2026). Defines scope for the
4-scalar leaf circuit security audit. Referenced by
`RELEASE_CHECKLIST.md` and `FCMP_PLUS_PLUS.md`.

## Build system

### Dead `i686_linux_*` target in `contrib/depends/hosts/linux.mk`
Deleted April 19, 2026. `linux.mk` defined an `i686_linux_*` cross
toolchain (`gcc -m32` / `g++ -m32`) inherited from Monero's Gitian
descriptor; nothing referenced it. The `i686-linux-gnu` target was
dropped from the Gitian matrix in V3.0 (see `docs/CHANGELOG.md` entry
"Gitian Linux: drop i686-linux-gnu"), no release workflow builds 32-bit
x86, and `shekyl-gui-wallet` has no 32-bit Linux target. Orphaned
package config options (`boost.mk $(package)_config_opts_i686_linux`,
`openssl.mk $(package)_config_opts_i686_linux`) and the stale README
build-target entry were removed in the same commit. The `i686-w64-mingw32`
Windows 32-bit target is independent and remains.

---

# Superseded items

Entries removed from the tracking documents because their framing
turned out to be wrong, and the real concern was tracked under
different (and more specific) items.

## Test code `wallet_tools.cpp` still uses mixin/decoy infrastructure

**Superseded April 19, 2026.** The original FOLLOWUPS.md entry framed
`wallet_tools::gen_tx_src` as "legacy test infrastructure that works
but is conceptually dead for Shekyl (no rings)," with a V3.2 target
for replacement. Investigation during the sweep found the situation
was more nuanced: the function carries a `DEPRECATED` comment but is
genuinely live on the Trezor test path
(`tests/trezor/trezor_tests.cpp:849`, `:1314`) with non-zero mixin
values, and the separate `chaingen.cpp` `nmix`-threading pattern is a
different concern from the `wallet_tools::gen_tx_src` path itself.
The original item was closed and replaced by three more accurate
items:

1. `docs/STRUCTURAL_TODO.md` §"Trezor test path still uses
   ring-signature test scaffolding" — coupled to PQC Multisig V3.1
   hardware-wallet integration (V3.2 code work). Not independently
   actionable.
2. `docs/FOLLOWUPS.md` §"`chaingen.cpp` carries a vestigial `nmix`
   parameter" — V3.2 cleanup of dormant parameter threading.
3. `docs/STRUCTURAL_TODO.md` §"Audit `tx_validation.cpp`
   non-zero-mixin tests" — audit-priority investigation of silent-pass
   test risk ahead of Phase 9 external review.

Moral: "legacy test infrastructure that's easy to delete" should be
greppable before it gets versioned.

---

# Chore #3 (v3.1.0-alpha.5) — 32-bit target retirement: security closure

Landed on `chore/retire-32bit-targets` branched from `dev`. Posture
correction, not a maintenance cleanup: **ARM32 cannot safely run Shekyl
wallet operations, and supporting the platform was a tacit lie about the
security posture of users on it.**

## Tightened five-claim framing

The canonical framing lives in `docs/STRUCTURAL_TODO.md` §"32-bit targets
cannot safely run Shekyl" (tightened in the first commit of this chore
from "operand-dependent carry propagation" to "libgcc helpers
(`__muldi3`, `__udivdi3`, `__ashldi3`) with no constant-time guarantee,
plus variable-latency `u64` multiply on common 32-bit ARM cores"; from
Cortex-M4 as the headline to **KyberSlash (Bernstein et al., 2024)** as
the headline with Cortex-M4 as supporting context; from FCMP++ "almost
certainly also broken" to the policy framing "has not been audited for
constant-time properties on 32-bit targets, and Shekyl will not take
responsibility for that audit across all 32-bit toolchains we would
otherwise ship"). That is the reviewer-facing copy.

In short:

1. `fips203` / `fips204` state their CT guarantees against native 64-bit
   arithmetic. On 32-bit targets the compiler emits libgcc helpers with
   no CT guarantee, plus variable-latency `u64` multiply on common
   32-bit ARM cores.
2. **KyberSlash (Bernstein et al., 2024)** is remote-timing-only against
   fielded CT implementations, broken by non-CT division — exactly what
   `__udivdi3`-on-32-bit instantiates.
3. The X25519 half of the hybrid is correctly CT on 32-bit; the hybrid
   construction does NOT rescue the ML-KEM secret once it leaks via
   timing.
4. FCMP++ proof generation on 32-bit is unaudited for CT; Shekyl
   declines responsibility for that audit.
5. `MDB_VL32` paged mmap + multi-second PQC verification per block make
   even node-only 32-bit operation impractical — sync time in weeks,
   different code path, untested against live block data.

Shipping a 32-bit daemon creates a reasonable user expectation that
wallet operation is supported, which it is not. Node-only support is
retired along with wallet support for that reason alone.

## Discovery narrative

- `070447f5b`, `9284d781d`, `a68314e3f`, `02a02e3c2` — misdiagnoses on
  `dev` and partial reverts, catalogued here so a reviewer doing history
  archaeology can follow the chain.
- `19d31723c` — `FindLibunwind` root-cause fix for the stack-trace
  regression that briefly masked the actual 32-bit issue.
- `886fc313d`, `159176067` — docs-only reframing that landed on `dev`
  during Chore #2's reverse-merge, pre-framing this chore with the
  "operand-dependent carry propagation" mechanism that Chore #3's
  `doc-tighten` commit replaces with the libgcc-helpers framing.
- CI runs `24720803048`, `24723150982`, `24728543538` — the failing
  runs that surfaced the 32-bit Windows mingw orphan, kicking off the
  "1-2 punch" docs framing that led here.

## Four independent tripwires (defense-in-depth)

A reverting PR must defeat all four. They are cross-referenced so a
contributor patching one immediately discovers the others.

1. **Tripwire D — `CMakeLists.txt`** (C++-side): first non-boilerplate
   block after `project(shekyl)`, fires at
   `NOT CMAKE_SIZEOF_VOID_P EQUAL 8` before any `find_package` /
   `include` / `add_subdirectory`. Exercised by
   `tests/cmake-gate-test/run.sh` (wired from
   `.github/workflows/cmake-gate-test.yml`) on every PR to `dev` — a
   PR that moves the gate below a probe fails that test.
2. **Tripwire A — `rust/shekyl-crypto-pq/src/lib.rs`** (primary
   ML-KEM/ML-DSA consumer): `compile_error!` on
   `not(target_pointer_width = "64")`. This is the gate that fires in
   practice on 32-bit builds in CI.
3. **Tripwire B — `rust/shekyl-ffi/src/lib.rs`**
   (structural-not-observable): cannot currently be unit-tested in
   isolation because `shekyl-ffi` transitively depends on
   `shekyl-crypto-pq` and Tripwire A fires first. This is structural,
   not observable — Tripwire B becomes independently observable only if
   a future refactor removes that transitive dependency, which is
   precisely the case it defends against. **A cleanup-PR argument of
   the form "this gate never fires, delete it" must be rejected.**
4. **Tripwire C — `rust/shekyl-tx-builder/src/lib.rs`** (direct
   `fips204` consumer on the transaction-signing hot path):
   independent of Tripwire A so a future refactor that narrows the
   dependency shape cannot silently drop the refusal.

## GUI / mobile / web / dev / monero-oxide repo scope

- **`shekyl-gui-wallet`** (Tauri): out of scope. Workflows (`ci.yml`,
  `release.yml`, `codeql.yml`) are 64-bit only. 17 `winapi-i686-*` /
  `windows_i686_*` hits in `src-tauri/Cargo.lock` are Cargo-registry
  metadata, not active build targets — **must not be "cleaned up"**.
  The GUI inherits the core's tripwires through the
  `shekyld-x86_64-unknown-linux-gnu` sidecar binary.
- **`shekyl-mobile-wallet`**, **`shekyl-dev`**, **`shekyl-web`**,
  **`monero-oxide`**: clean.

## `tests/hash/main.cpp` disambiguation (anti-false-positive)

Lines 192 and 206 in `tests/hash/main.cpp` guard `<emmintrin.h>` SSE
intrinsic includes behind `__x86_64__ || (_MSC_VER && _WIN64)`. **These
are x86_64 arch gates, not 32-bit gates.** Deleting them would break
aarch64 builds. The pre-Chore-#3 framing in `STRUCTURAL_TODO.md`
imprecisely suggested they were 32-bit-only — the hazard table has
been corrected and this entry records the disambiguation for future
auditors.

## Deletions (summary)

Build system: `cmake/32-bit-toolchain.cmake` (whole file);
`Makefile` 32-bit targets (`release-static-win32`,
`release-static-linux-i686`, `release-static-android-armv7`,
`release-static-linux-armv6`, `release-static-linux-armv7`,
`debug-static-win32`) plus `-D BUILD_64=ON` from all remaining 64-bit
targets; `CMakeLists.txt` `BUILD_64` / `DEFAULT_BUILD_64` / `ARCH_WIDTH`
/ `ARM_TEST` / `ARM6` / `ARM7` machinery and the Clang+32 libatomic
workaround; `src/blockchain_utilities/CMakeLists.txt` `ARCH_WIDTH`
block; `src/blockchain_utilities/blockchain_import.cpp` `#if ARCH_WIDTH
!= 32` conditional (body retained, guard deleted); `external/db_drivers/
liblmdb/CMakeLists.txt` `MDB_VL32` define site; `contrib/depends/`
(toolchain template `i686`/`armv7`/`BUILD_64`/`LINUX_32` branches,
package recipes for boost/openssl/android_ndk/unbound arch-asymmetric
32-bit lines, `README.md` host list, `.gitignore` `i686*`/`arm*` entries,
`packages.md` example), `cmake/BuildRust.cmake` all non-64-bit
CMAKE_SYSTEM_PROCESSOR branches; gitian configs (`gitian-linux.yml`,
`gitian-android.yml`, `gitian-win.yml`) 32-bit hosts/alternatives.

C/C++ conditionals: `src/common/compat/glibc_compat.cpp`
`__wrap___divmoddi4` block and `__i386__`/`__arm__` glob symver arms +
the corresponding `-Wl,--wrap=__divmoddi4` linker flag in root
`CMakeLists.txt`; `src/crypto/slow-hash.c` L1015 outer guard narrowed
from `__arm__ || __aarch64__` to `__aarch64__` (inner
`#ifdef __aarch64__` collapsed to always-true and the 32-bit fallback
`cn_slow_hash_{allocate,free}_state` stubs removed); `src/crypto/
CryptonightR_JIT.{c,h}`, `src/crypto/CryptonightR_template.h` x86 gates
narrowed from `__i386 || __x86_64__` to `__x86_64__`;
`src/cryptonote_basic/miner.cpp` FreeBSD APM gates narrowed from
`__amd64__ || __i386__ || __x86_64__` to `__amd64__ || __x86_64__`;
`src/blockchain_db/lmdb/db_lmdb.h` `__arm__` DEFAULT_MAPSIZE branch
removed; `src/blockchain_db/lmdb/db_lmdb.cpp` `MISALIGNED_OK` gate
narrowed to `__x86_64` only.

Rust: three `compile_error!` tripwires (A/B/C) with distinct,
cross-referencing messages per the "duplicated by design" framing;
`rust/shekyl-oxide/crypto/helioselene/benches/helioselene.rs`
`target_arch = "x86"` branches collapsed to `x86_64` only.

CI: `.github/workflows/depends.yml` ARM v7 commented-out stub replaced
with a pointer to this chore; new `.github/workflows/cmake-gate-test.yml`
+ `tests/cmake-gate-test/` (fake 32-bit toolchain file + `run.sh`
asserting non-zero exit, gate message + KyberSlash citation in stderr,
no `find_package` output).

Docs: `README.md`, `docs/INSTALLATION_GUIDE.md`, `docs/RELEASING.md`,
`docs/COMPILING_DEBUGGING_TESTING.md` all rewritten to 64-bit-only;
`docs/VENDORED_DEPENDENCIES.md` LMDB/`MDB_VL32` note;
`docs/STRUCTURAL_TODO.md` §"32-bit targets cannot safely run Shekyl"
tightened and closure paragraph added; `docs/FOLLOWUPS.md` Chore #3
entry tightened and moved to V3.1.x; `docs/CHANGELOG.md` `[Unreleased]
### Security` entry leading with the tacit-lie framing.

**Delete, don't `#if 1`:** every removed conditional is deleted
outright. A dead `#if ARCH_WIDTH == 64` invites future contributors to
assume a meaningful 32-bit alternative exists somewhere and reason
about it.

---

# Source-document snapshot metadata

- Swept from `docs/STRUCTURAL_TODO.md` as of its state after
  `613b14e55` (POSIX header consolidation).
- Swept from `docs/FOLLOWUPS.md` as of its state after
  `613b14e55`.
- Subsequent work: items remaining in the tracking documents after
  this sweep are **open**. Treat an item's absence from this file as
  evidence it was open at sweep time, not as evidence it never
  existed — always check prior revisions of the tracking documents in
  git history for the full record.
