# Structural TODOs — shekyl-core

Issues discovered during the MSVC wallet-core enablement (branch
`feature/msvc-wallet-core`). These are genuine structural weaknesses, not
just one-off portability patches. Tracked here so they survive branch
switches in shekyl-core.

---

## Platform Abstraction Gaps

### ~~`ssize_t` not centralized~~ ✅ Resolved
Created `src/common/compat.h` with the centralized `ssize_t` typedef
for MSVC. Both `util.h` and `download.h` now `#include "common/compat.h"`
instead of inline guards. *(Landed on `dev` in `f275a6a3b`; merged to
`feature/msvc-wallet-core` in `93440c429`.)*

### Unconditional POSIX includes scattered across 6+ files — partially resolved
`unistd.h`, `dlfcn.h`, `sys/mman.h` were individually guarded with
`#ifndef _WIN32` or `#if !defined(_MSC_VER)` in `util.cpp`,
`stack_trace.cpp`, `slow-hash.c`, `rx-slow-hash.c`, `aligned.c`,
`spawn.cpp`, `keccak.c`, `CryptonightR_JIT.c`. Individual guards are in
place and `util.cpp` now has full MSVC coverage (`<io.h>`, `setenv`→
`putenv`, `umask`→noop, `closefrom`→noop on `_WIN32`). A centralized
platform-compat header would still prevent future regressions from
upstream cherry-picks or new code.

### ~~`xor` used as a C parameter name in `slow-hash.c`~~ ✅ Resolved
Renamed to `xor_pad` in both x86/SSE and ARM/NEON variants of
`aes_pseudo_round_xor()`. *(Landed on `feature/msvc-wallet-core` in
`bb5763742`.)*

---

## Language Standard Drift

### ~~C++20 designated initializers in a C++17 codebase~~ ✅ Resolved
All 10 call sites across 6 files (`blockchain.cpp`, `cryptonote_core.cpp`,
`levin_notify.cpp`, `multisig_tx_builder_ringct.cpp`, `wallet2.cpp`)
rewritten from `{.field = val}` to C++17 member assignment. *(Landed on
`dev` in `f275a6a3b`; merged to `feature/msvc-wallet-core` in
`93440c429`.)* **Remaining action:** ~~Audit for other C++20-isms
(concepts, ranges, `std::format`, coroutines, `<=>` operator) that
GCC/Clang silently accept but MSVC doesn't.~~ ✅ Audited April 2026:
no designated initializers, `std::format`, concepts, ranges, or `<=>`
found in `src/`.

### C++ alternative tokens (`not`, `and`, `or`) used extensively
Hundreds of call sites use `not` instead of `!`, `and` instead of `&&`,
etc. MSVC does not treat these as keywords by default. Current workaround:
`/FIiso646.h` in `CMAKE_CXX_FLAGS`. **Long-term options:**
1. Adopt `/permissive-` for full C++ conformance on MSVC.
2. Standardize on `!` / `&&` / `||` operators (large mechanical change).
3. Keep the `/FIiso646.h` workaround (simplest, but fragile).

**Decision (April 2026):** Keep option 3 (`/FIiso646.h`). The mechanical
change to replace hundreds of `not`/`and`/`or` sites is high-effort,
low-value, and risks merge conflicts with upstream Monero cherry-picks.
Revisit if the codebase adopts `/permissive-` (option 1).

### ~~MSVC treats `xor` as reserved in C mode~~ ✅ Resolved
Even after moving `/FIiso646.h` to C++ only, MSVC rejects `xor` as a
parameter name in C files. MSVC appears to reserve C++ alternative tokens
even in C mode. The `slow-hash.c` parameter was renamed to `xor_pad` in
both x86/SSE and ARM/NEON variants. *(Landed on `feature/msvc-wallet-core`
in `bb5763742`.)* Any future C code using `xor`, `and`, `or`, etc. as
identifiers should avoid these names.

### ~~`__thread` TLS qualifier not portable~~ ✅ Resolved
Replaced `__thread` with standard `thread_local` (C++11) in all three
files: `easylogging++.cc` *(landed on `dev` in `f275a6a3b`)*, and
`perf_timer.cpp` + `threadpool.cpp` *(landed on `dev` in `17fb55648`;
originally on `feature/msvc-wallet-core` in `5dcef4bdc`)*.

### ~~MSVC iterator types are classes, not raw pointers~~ ✅ Resolved
`boost::as_literal()` returns iterators that are classes on MSVC
(`std::_Array_const_iterator`), not raw `const char*`. Code that
`reinterpret_cast`s iterators to pointers breaks. Fixed in epee's HTTP
auth code by casting through `&*it` (dereference then address-of) to
obtain a raw pointer portably. *(Landed on `feature/msvc-wallet-core` in
`d92533e34`.)* Other similar patterns may exist in epee.

### ~~`unbound.h` include not guarded in `util.cpp`~~ ✅ Resolved
The `#include "unbound.h"` and `unbound_built_with_threads()` function
body/call site were not wrapped in `HAVE_DNS_UNBOUND`. Added
`#ifdef HAVE_DNS_UNBOUND` guards around the include and all call sites in
`util.cpp`. *(Landed on `feature/msvc-wallet-core` in `bb5763742`.)*

---

## Dead / Broken Code Discovered

### ~~`throw_wallet_ex` MSVC Boost.PP fallback was broken for years~~ ✅ Resolved
Removed the dead Boost.PP overload-generation code path and unified on the
variadic template version with `/Zc:preprocessor` for conformant macro
expansion. *(Landed on `feature/msvc-wallet-core` in `feda06508`.)*
**Lesson:** MSVC-specific code paths need CI coverage to avoid bit-rot.

### ~~`portable_storage` overly strict `static_assert`s~~ ✅ Resolved
Removed the three overly strict `static_assert`s and changed
`portable_storage_base.h` from rvalue-ref to pass-by-value parameters.
*(Landed on both `dev` in `c10368e9d` and `feature/msvc-wallet-core` in
`8a4a6c29f`.)* **Remaining action:** Consider explicit template
instantiation tests for the serialization layer to catch deduction issues
across compilers.

---

## Third-Party / Dependency Issues

### ~~easylogging++ vendored with no MSVC support~~ ✅ Resolved
`external/easylogging++/easylogging++.cc` had three issues, all now fixed:
unconditional `#include <unistd.h>` (guarded in `d92533e34`), `__thread`
TLS (replaced with `thread_local` in `f275a6a3b`), and hardcoded `-fPIC`
in CMakeLists.txt (replaced with `POSITION_INDEPENDENT_CODE ON` in
`0730a7bd4`). All three fixes confirmed in tree April 2026.
The library is unmaintained upstream and any future MSVC
issues will require local patches. **Options:**
1. Maintain a local fork with MSVC patches (current approach).
2. Replace with `spdlog` or another maintained logging library (larger
   effort but long-term benefit).

### `libunbound` completely stubbed on MSVC
`dns_utils.cpp` is wrapped in `#ifdef HAVE_DNS_UNBOUND` with no-op stubs
in the `#else` branch. This means wallet DNS resolution (OpenAlias address
lookup, DNS checkpoint fetching) silently does nothing on MSVC/Windows
builds. **Options:**
1. Port `libunbound` to vcpkg (it exists in some forks).
2. Implement a Windows-native DNS backend using `DnsQuery_A` / `DnsQueryEx`.
3. Accept the limitation for GUI wallet (which may not need CLI DNS
   features).

### ~~`boost::iterator_range` constructor regression with Boost 1.90~~ ✅ Resolved
`http_auth.cpp` used `boost::iterator_range<const char*>` with
`boost::as_literal()`, which returns a different iterator type in Boost
1.90 on MSVC. Fixed by switching to `auto` deduction so the type adapts
to whatever `boost::as_literal()` returns. *(Landed on
`feature/msvc-wallet-core` in `d92533e34`.)* **Remaining action:** Watch
for similar Boost 1.90 regressions in other epee / Monero-inherited code.

### MSVC warnings in vendored dependencies
**Priority**: Low — external code, but worth tracking

MSVC CI reveals several warnings in vendored/external code:
- **`liblmdb/mdb.c:1745`** — C4172: returning address of local `buf`
  (dangling pointer — genuine bug, but in a debug-only code path)
- **`liblmdb/mdb.c:8417`** — C4333: right shift too large (data loss)
- **`liblmdb/mdb.c:939,7840`** — C4146: unsigned negation
- **`easylogging++.cc:2576`** — C4333: right shift too large
- **`randomx/blake2.h:82,84`** — C4804: bool used in division

None are in hot paths for wallet-core, but the liblmdb dangling pointer
could bite if that code path is ever exercised. These should be
reported upstream or patched locally if we diverge from upstream.

---

## CI / Build Hygiene

### vcpkg builds take 45+ minutes — partially resolved
Even with `actions/cache` for binary packages, the vcpkg install step
takes 45+ minutes on cold runs and 10-15 minutes on warm cache hits.
~~There is no `vcpkg.json` manifest — packages are listed in the CI YAML.~~
✅ Root `vcpkg.json` manifest created (April 2026) with the 5 dependencies
(boost, openssl, libsodium, libusb, lmdb). **Remaining:** Update CI YAML
to use `vcpkg install --x-manifest-root=.` instead of explicit package list,
and verify cache key hashing improves.

### ~~No CI guard against `BOOST_FOREACH` re-introduction~~ ✅ Resolved
31 `BOOST_FOREACH` / `BOOST_REVERSE_FOREACH` sites were manually replaced
with range-based for loops *(cherry-picked to `dev` in `591e3b5ee` and
`ee8ea9719`; originally on `feature/msvc-wallet-core` in `7eb61302b` and
`fe5b076a7`)*. CI lint step added to `.github/workflows/build.yml` that
fails if any `BOOST_FOREACH` matches are found. *(Landed in PR-cleanup,
April 2026.)*

### ~~`NOMINMAX` required on MSVC~~ ✅ Resolved
Added `/DNOMINMAX` to the MSVC `add_definitions` to prevent Windows
`min`/`max` macro collisions with `crypto.h`. *(Cherry-picked to `dev` in
`591e3b5ee`; originally on `feature/msvc-wallet-core` in `7eb61302b`.)* This
is a well-known Windows
issue but was never needed before because MSVC was never tested. If any
future code includes `<windows.h>` before `NOMINMAX` is defined, the
collision will resurface.

### ~~MSVC Internal Compiler Error on `obj_blocks` and `obj_cncrypto`~~ ✅ Resolved
Both ICEs are resolved. The `obj_blocks` ICE was caused by
`const unsigned char name[]={};` (empty array initializer) generated from
0-byte `.dat` files; the generator now emits `{0x00}` with `_len = 0`.
The `obj_cncrypto` ICE was caused by `CryptonightR_JIT.c` and its
heavyweight includes (`variant4_random_math.h`, `CryptonightR_template.h`)
overwhelming the PDB type server. A stub (`CryptonightR_JIT_stub.c`)
replaces it on MSVC, providing the same `return -1` without the
problematic headers. The ICE reproduces on both MSVC 14.44 (VS 2022)
and 14.50 (VS 2026) -- the stub is the actual fix, not a compiler
upgrade. Full diagnosis in `shekyl-core/docs/COMPILING_DEBUGGING_TESTING.md`.

### `COVERAGE=ON` applies GCC-only flags without MSVC guard
**Priority**: Low
`monero_enable_coverage()` in root `CMakeLists.txt` appends
`-fprofile-arcs -ftest-coverage --coverage` to `CMAKE_C/CXX_FLAGS` with
no `if(NOT MSVC)` guard. Enabling `COVERAGE` on an MSVC build would pass
unrecognized flags. Nobody enables coverage on MSVC today, but the option
should be gated.

### `enable_stack_trace` linker flag not MSVC-safe
**Priority**: Low
`src/CMakeLists.txt` appends `-Wl,--wrap=__cxa_throw` to `LINK_FLAGS`
when `STATIC` is set, with no MSVC guard. This is GNU `ld` syntax that
MSVC's linker would reject. Only triggers for `STATIC + STACK_TRACE`
builds, which are not currently done on MSVC.

---

## Data Type Portability

### `long` is 32-bit on MSVC x64 — several format/parse mismatches
**Priority**: Medium (not in wallet-core library, but affects CLI tools)

On 64-bit MSVC, `long` / `unsigned long` are 32 bits (LLP64 model) vs
64 bits on Linux (LP64). ~~Several sites outside the wallet-core library
used `long` for values that can exceed 32 bits.~~ `simplewallet.cpp`
has been deleted from the repository; its two sites no longer exist.
One active site remains:

- **`bootstrap_file.cpp:~194`**: `tellp()` stream positions stored in
  `long` and cast to `unsigned long`. Large blockchain exports would
  overflow. **Fix:** Use `std::streamoff` / `int64_t`.
- **Various display code**: `boost::format` with `%lu` and
  `(unsigned long)uint64_t_value` truncates on MSVC. **Fix:** Use
  `PRIu64` or stream insertion.

### ~~`blockchain_import.cpp` uses POSIX `sleep()`~~ ✅ Resolved
Replaced `sleep(90)` with `std::this_thread::sleep_for(std::chrono::seconds(90))`
in `blockchain_import.cpp`. *(Landed on `feature/msvc-wallet-core` in
`fda82e3d4`.)*

### ~~32-bit shift widened to 64-bit — 23 sites in consensus code (C4334)~~ ✅ Resolved
**Priority**: Was medium — potential UB if shift amount ever reached 32

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

### ~~Right shift by too-large amount — data loss (C4333)~~ ✅ Resolved
**Priority**: Was medium — actual data loss on MSVC

- **`src/common/util.cpp`** — Changed `wint_t cp` to `uint32_t cp` in
  `get_string_prefix_by_width()`. On MSVC, `wint_t` is 16-bit
  `unsigned short`, so `cp >> 18` shifted by more than the type width.
- **`src/common/utf8.h`** — Added `static_cast<uint32_t>` on the
  transform result in `utf8canonical()` to ensure proper type widening.

*(Fixed on `dev` branch, April 2026.)*

### ~~Unsafe bool/char mixing in `wallet2.h:2324` (C4805)~~ ✅ Resolved
Line/pattern no longer exists after wallet refactoring (`wallet2.h` is
now 2144 lines; `|=` bool/char pattern not found).

### Unsigned negation in `wallet2.cpp:772` (was 782) (C4146)
**Priority**: Low — well-defined but suspicious

Line shifted to 772 after wallet refactoring. Pattern is
`std::advance(left, -N)` where `N` is `size_t` — unsigned negation.
Well-defined C++ (wraps to `UINT_MAX - n + 1`) but worth fixing with
a `static_cast<ptrdiff_t>` for clarity and MSVC warning suppression.

---

## Unsafe `memcmp` Usage

Audit of all 111 first-party `memcmp` call sites (25 in `src/`, 2 in
`contrib/`, 84 in `tests/`) revealed three classes of problems: a
correctness bug on non-POD structs, timing-unsafe comparisons on secret
material, and inconsistent use of the existing constant-time comparison
infrastructure.

### ~~🔴 CRITICAL — `memcmp` on `account_public_address` (non-POD struct)~~ ✅ Resolved
**Priority**: Was critical — **broken before fix**, not a theoretical risk

`account_public_address` contains `std::vector<uint8_t> m_pqc_public_key`.
`memcmp` over such a struct compared vector bookkeeping, not key bytes.

**Resolution (Shekyl):** `operator==` / `operator!=` already compared
`m_spend_public_key`, `m_view_public_key`, and `m_pqc_public_key`
member-wise in `cryptonote_basic.h`. All production `memcmp` sites on
`account_public_address` (`wallet2.cpp`, `wallet2_ffi.cpp`,
`wallet_rpc_server.cpp`, `unsigned_transaction.cpp`)
now use `==` / `!=`. (`simplewallet.cpp` was deleted from the
repository.) Added
`static_assert(!std::is_trivially_copyable_v<account_public_address>)`
after the struct to discourage future raw `memcmp` on the type.

### ~~🟡 MEDIUM — `memcmp` on secret / HMAC material (timing attack risk)~~ ✅ Resolved
**Priority**: Was medium — local-access timing side channels

**Resolution (Shekyl):** `wallet2::is_deterministic` now uses
`crypto_verify_32` for the view-secret check. Ledger `HMACmap::find_mac`
uses `crypto_verify_32` for secret lookup. Both replace short-circuiting
`memcmp` on 32-byte secrets.

### ~~🟢 LOW — Inconsistent constant-time macro usage in `generic-ops.h`~~ ✅ Resolved
**Priority**: Was low — no current vulnerability, but a footgun

All 32-byte types (`public_key`, `key_image`, `hash`) now use
`CRYPTO_MAKE_HASHABLE_CONSTANT_TIME` → `crypto_verify_32`. The
non-constant-time `CRYPTO_MAKE_COMPARABLE` is retained only for
non-32-byte types (`signature` at 64 bytes, `view_tag` at 1 byte,
`hash8` at 8 bytes) where `crypto_verify_32` does not apply. This
eliminates the footgun of choosing the wrong macro for new 32-byte types.

### Additional `memcmp` notes

**Safe but worth documenting:**
- `tx_pool.cpp:1656` — `memcmp(&original_meta, &meta, sizeof(meta))`:
  ✅ **Audited.** `static_assert` added to enforce trivially-copyable
  layout and 192-byte struct size. All padding and new fields
  (`fcmp_verification_hash`, `fcmp_verified`) are zero-initialized
  at every meta construction site in `add_tx`.
- `wallet2.cpp:13170,14260` — file magic comparisons: byte-array
  literals, no issues.
- `wallet2.cpp:10834` — `std::memcmp` on raw `data()` of public key
  blob at a computed offset: correct for fixed-size byte arrays.
- `crypto.cpp:335`, `rx-slow-hash.c:75-76` — byte-array comparisons
  against constants: no issues.
- ~90 test-only `memcmp` calls (updated April 2026): low priority, but
  `tests/` should adopt `operator==` as production code is migrated.

**Prerequisite:** Core wallet correctness fixes in `shekyl-dev`
`docs/STRUCTURAL_TODO.md` (e.g. `account_public_address` must not be compared
with `memcmp` once PQC keys live in a `std::vector`) should land in
shekyl-core before large epee removals.

---

## Naming / Code Clarity

### `rct_signatures` field name is a Monero-era misnomer — partially addressed
**Priority**: Low — cosmetic, but misleading

`transaction::rct_signatures` (typed `rct::rctSig`) no longer holds ring
signatures. In Shekyl v3, the only accepted types are `RCTTypeNull`
(coinbase) and `RCTTypeFcmpPlusPlusPqc`. The struct actually carries:

- **`rctSigBase`**: Pedersen commitments (`outPk`), HKDF-encrypted amounts
  (`enc_amounts`), `txnFee`, `referenceBlock` (curve tree anchor),
  `pseudoOuts`.
- **`rctSigPrunable`**: BP+ range proofs, the opaque FCMP++ membership
  proof, `curve_trees_tree_depth`.

All ring signature types (`RCTTypeFull`, `RCTTypeSimple`, `RCTTypeCLSAG`,
`RCTTypeBulletproof`, `RCTTypeBulletproofPlus`) are rejected at
deserialization. The name "rct" (Ring Confidential Transactions) is
misleading since the ring component no longer exists.

**Status (April 2026):** `using ct_signatures = rct::rctSig;` type alias
added in `cryptonote_basic.h`. New code should use `ct_signatures` for the
type. The full caller migration and `rct::` namespace rename to `ct::` are
deferred to V4 when Monero upstream cherry-picks end.

The `rct::` namespace (`src/fcmp/rctTypes.h`, `rctOps.h`, `rctSigs.h`)
has the same problem — it was renamed from `ringct/` to `fcmp/` at the
directory level but retains the `rct::` namespace internally.

---

## Upstream Techniques to Track

Cross-references to Monero upstream PRs whose structural techniques are
relevant to items above. See `shekyl-core/docs/COMPILING_DEBUGGING_TESTING.md`
(upstream triage section) for full status. See `FCMP_BUILD_PLAN.md`
(formerly `FCMP_MIGRATION_PLAN.md`) for the complete FCMP++ implementation
plan.

- **Monero #10157 — Mempool input verification caching.**
  **Status: ✅ COMPLETE (Phase 4b).**
  `txpool_tx_meta_t` now stores a 32-byte `fcmp_verification_hash` and a
  1-bit `fcmp_verified` flag (carved from the 76-byte padding, now 44
  bytes). `compute_fcmp_verification_hash()` produces a deterministic
  cache key from `hash(proof || referenceBlock || key_images)`.
  `is_transaction_ready_to_go` seeds `m_input_cache` from the meta hash
  to skip `shekyl_fcmp_verify()` for previously-verified mempool txs.
  `static_assert`s at the `memcmp` site (tx_pool.cpp) enforce struct
  size and layout. Full FCMP++ verification pipeline (Phases 1-6)
  complete. See `docs/FCMP_PLUS_PLUS.md` in shekyl-core for the
  complete specification.
- **Monero #10084 — `wallet2_basic` library extraction.** Decomposes
  monolithic `wallet2` into minimal file-I/O types. Relevant to the
  MSVC ICE on `obj_blocks`/`obj_cncrypto` (smaller TUs sidestep ICEs)
  and to the wallet Rust migration (extracted types map to what needs
  Rust equivalents). Shekyl's parallel path is `wallet2_ffi.cpp`.
- **Monero #9801 — Rust in Guix reproducible builds.**
  **Status: 🔴 BLOCKING for reproducible release.**
  Three Rust crates now in the build (`shekyl-crypto-pq`, `shekyl-ffi`,
  `shekyl-fcmp`). Rust cross-arch builds are NOT bit-identical.
  x86_64-only build requirement for release artifacts. Key constraint:
  must be resolved before the Guix reproducible release pipeline can
  produce official binaries.
  See `FCMP_BUILD_PLAN.md` for the complete implementation plan.

---

*Last updated: 2026-04-12 — Consensus-critical curve-tree leaf ordering
bug fixed (DB v6→v7): `MDB_DUPSORT` on leaf bytes replaced with composite
keys, explicit output↔leaf mapping tables, and block-pending journal. API
renamed (`get_curve_tree_leaf` → `get_curve_tree_leaf_by_tree_position` +
`get_curve_tree_leaf_by_output_index`). Stake claim validation tightened
with leaf recomputation. Typed wrappers in `shekyl_types.h`. 4 regression
tests added. See `LMDB_SCHEMA.md` §v6→v7 and `FCMP_PLUS_PLUS.md`
deferred insertion section. Previous: Added `rct_signatures` naming issue.
C4334 (23 sites) and C4333 (2 sites) fixes landed on `dev`. FCMP++ Phases
1-7 complete (Phase 7 = CLSAG / dead code purge). Monero #10157
verification caching complete. BOOST_FOREACH CI guard added.
`json_serialization` test reworked from stub to real FFI-based FCMP++
transaction construction. `rctSig` JSON serializer fixed to round-trip
`message` and `referenceBlock` fields. `core_tests` FCMP++ proof
verification failures fixed: added per-height `m_curve_tree_roots` LMDB
table so that both prover and verifier read the correct historical tree
root (replacing block-header placeholder). `compute_leaf_count_at_height`
aligned with production `collect_outputs`. `vcpkg.json` manifest removed
(broke MSVC CI). See `FCMP_BUILD_PLAN.md` for remaining Phases 8-9
(multisig integration, testing/audit).*
