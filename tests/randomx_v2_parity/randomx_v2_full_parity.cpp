// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// @file randomx_v2_full_parity.cpp
/// @brief Phase 3a Hole-1 gate: RandomX v2 C **full-dataset** vs Rust
///        **light-cache** PoW parity.
///
/// The Rust consensus verifier (`shekyl_pow_randomx_v2_hash`, light-cache
/// only) and the RandomX v2 C library a miner runs (full ~2 080 MiB dataset
/// fast mode) must produce byte-identical hashes for every
/// `(seedhash, blob)`. RandomX guarantees light == full, but the Phase 2g
/// differential harness only compared Rust-light vs C-**light**
/// (`randomx-v2-sys` is light-only by design), so the full-dataset path had
/// never been differentially checked against the Rust verifier. This test
/// closes that gap — it is the actual cutover invariant per
/// `docs/design/RANDOMX_V2_PHASE3_PLAN.md` §7.
///
/// Construction (§7.2 #1): the C reference is built **directly** —
/// `randomx_alloc_cache` -> `randomx_init_cache` -> `randomx_alloc_dataset`
/// -> `randomx_init_dataset` -> `randomx_create_vm(flags | FULL_MEM | V2)` ->
/// `randomx_calculate_hash` — bypassing `rx-slow-hash.c`'s async light/full
/// state machine. `RANDOMX_FLAG_V2` is threaded through cache, dataset, and
/// VM exactly as the library's own `src/tests/benchmark.cpp` mining path
/// does; its omission was the PR #79 divergence.
///
/// Corpus (§7.2 #2): two seeds, each exercised in its **own process** (see
/// "one dataset per process" below), selected by `argv[1]`:
///
///   - `genesis`   : the real genesis `(seedhash = genesis block id,
///                   blob = genesis hashing blob)` derived at runtime
///                   through the production consensus path
///                   (`generate_genesis_block` + `get_block_hash` +
///                   `get_block_hashing_blob`), plus an extra blob-shaped
///                   input under the same seed. This is the consensus-
///                   relevant seed.
///   - `canonical` : a fixed seed `0x01..0x20` (an independent dataset),
///                   carrying an in-process full-dataset KAT frozen as a
///                   regression anchor (§7.2 #3 caveat below), plus an extra
///                   blob. A second independent seed guards against the
///                   parity being a fluke of one dataset.
///
/// One dataset per process: each ~2 080 MiB dataset is allocated and
/// released in its own process invocation (`genesis` / `canonical`), so peak
/// memory stays at one dataset and a failure is isolated to its seed. ctest
/// drives the two modes as separate processes (see this directory's
/// `CMakeLists.txt`).
///
/// Library teardown bug: librandomx's global `SuperscalarInstructionInfo`
/// objects double-free their `std::vector<MacroOp>` members when the shared
/// library is unloaded at process exit (confirmed by a gdb backtrace through
/// `_dl_fini` -> `__do_global_dtors_aux` -> `~SuperscalarInstructionInfo`).
/// This is a teardown-only defect: it fires after the parity result is
/// computed and printed, independent of hash correctness. `main` exits via
/// `std::_Exit` to bypass the broken static destructors so the abort cannot
/// mask the real verdict. The upstream bug is tracked in
/// `docs/FOLLOWUPS.md`.
///
/// Halt-on-red (§7.3): a mismatch is **not** a test bug. It is a discovery
/// that the v2 library's light and full modes diverge at the pinned commit
/// `aaafe71`, which would mean the light-only Rust verifier cannot validate
/// full-dataset-mined blocks at all. The disposition is to **halt the
/// cutover and escalate** for an architecture rethink, not to patch this
/// test or proceed to Phase 3b.
///
/// KAT provenance caveat (§7.2 #3): the frozen `kFrozenKatHashHex` below is
/// captured from this in-process full-dataset computation, not from a
/// separate-process miner run. It is a regression anchor against library /
/// flag drift, which the live C-full == Rust-light comparison already
/// proves on every run. Capturing a hash from an actual v2 mining run to
/// close the in-process-proxy gap is tracked in `docs/FOLLOWUPS.md`.
///
/// Gating: release-gate only (ctest label `randomx_v2_full_parity`); the
/// ~2 080 MiB dataset is minutes to allocate and initialize, so this is not
/// part of the per-PR fast gate. Run with `ctest -L randomx_v2_full_parity`
/// (executes both the `genesis` and `canonical` invocations).

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <randomx.h>

#include "shekyl/shekyl_ffi.h"

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

namespace
{
  using Hash32 = std::array<uint8_t, 32>;

  std::string to_hex(const uint8_t *p, size_t n)
  {
    static const char *digits = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
      s.push_back(digits[p[i] >> 4]);
      s.push_back(digits[p[i] & 0x0f]);
    }
    return s;
  }

  // A single (seed, blob) parity case. `is_kat` entries additionally assert
  // against the frozen regression hash when one is pinned.
  struct Case
  {
    std::string label;
    Hash32 seed;
    std::vector<uint8_t> blob;
    bool is_kat = false;
  };

  // ---- C full-dataset reference ----------------------------------------

  // Owns the cache/dataset/VM for one seed. The dataset is ~2 080 MiB and is
  // rebuilt per distinct seed; cases are grouped by seed to amortize it.
  struct CFullVm
  {
    randomx_cache *cache = nullptr;
    randomx_dataset *dataset = nullptr;
    randomx_vm *vm = nullptr;

    CFullVm() = default;
    CFullVm(const CFullVm &) = delete;
    CFullVm &operator=(const CFullVm &) = delete;

    ~CFullVm()
    {
      if (vm)
        randomx_destroy_vm(vm);
      if (dataset)
        randomx_release_dataset(dataset);
      if (cache)
        randomx_release_cache(cache);
    }
  };

  // Flags mirror the library's own mining path (src/tests/benchmark.cpp):
  // the hardware-recommended perf flags from randomx_get_flags() (JIT,
  // hardware AES, the Argon2 variant) plus the two flags the verifier
  // semantics require — FULL_MEM (use the dataset) and V2 (the v2
  // algorithm). The perf flags do not change the hash value; FULL_MEM must
  // not (that is the invariant under test); V2 must be present on every
  // structure or the result is a v1 hash (PR #79).
  randomx_flags full_flags()
  {
    return randomx_get_flags() | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2;
  }

  bool build_c_full(const Hash32 &seed, CFullVm &out, std::string &err)
  {
    const randomx_flags flags = full_flags();

    out.cache = randomx_alloc_cache(flags);
    if (!out.cache)
    {
      err = "randomx_alloc_cache failed";
      return false;
    }
    randomx_init_cache(out.cache, seed.data(), seed.size());

    out.dataset = randomx_alloc_dataset(flags);
    if (!out.dataset)
    {
      err = "randomx_alloc_dataset failed (~2 080 MiB)";
      return false;
    }

    // Single-threaded dataset initialization (benchmark.cpp's
    // initThreadCount==1 branch). Dataset init dominates this gate's
    // runtime, but it is a release-only gate, so the simpler, deterministic
    // single-threaded fill is preferred over the disjoint-range thread pool.
    const unsigned long item_count = randomx_dataset_item_count();
    randomx_init_dataset(out.dataset, out.cache, 0, item_count);

    // The cache is no longer needed once the dataset is initialized.
    randomx_release_cache(out.cache);
    out.cache = nullptr;

    out.vm = randomx_create_vm(flags, nullptr, out.dataset);
    if (!out.vm)
    {
      err = "randomx_create_vm(FULL_MEM|V2) failed";
      return false;
    }
    return true;
  }

  void c_full_hash(randomx_vm *vm, const std::vector<uint8_t> &blob, Hash32 &out)
  {
    randomx_calculate_hash(vm, blob.data(), blob.size(), out.data());
  }

  // ---- Rust light verifier (FFI) ---------------------------------------

  bool rust_light_hash(const Hash32 &seed, const std::vector<uint8_t> &blob, Hash32 &out)
  {
    const int32_t rc = shekyl_pow_randomx_v2_hash(
      reinterpret_cast<const uint8_t (*)[32]>(seed.data()),
      blob.data(),
      blob.size(),
      reinterpret_cast<uint8_t (*)[32]>(out.data()));
    return rc == SHEKYL_POW_RANDOMX_V2_OK;
  }

  // ---- Corpus ----------------------------------------------------------

  // Frozen in-process full-dataset KAT (see file header §7.2 #3 caveat).
  // Empty string => capture mode: the test prints the computed hash and
  // skips the frozen assertion (but still asserts C-full == Rust-light).
  // Paste the printed hex here to arm the regression anchor.
  //
  // Captured in-process (FLAG_V2|FULL_MEM) at pin aaafe71 over the canonical
  // seed 0x01..0x20 and kKatBlobAscii below.
  const char *const kFrozenKatHashHex =
    "34f8b0179159d837e463c17c8692c106d2d3536f7da325aeefeb3e22a136b651";

  // Fixed KAT input under the canonical seed (0x01..0x20).
  const char *const kKatBlobAscii =
    "Shekyl RandomX v2 full-dataset parity KAT (Phase 3a, pin aaafe71)";

  std::vector<uint8_t> ascii_bytes(const char *s)
  {
    return std::vector<uint8_t>(s, s + std::strlen(s));
  }

  // Deterministic, blob-shaped filler distinct from the KAT input.
  std::vector<uint8_t> pattern(size_t n)
  {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i)
      v[i] = static_cast<uint8_t>((i * 131 + 7) & 0xff);
    return v;
  }

  bool genesis_case(Case &out, std::string &err)
  {
    cryptonote::block bl{};
    if (!cryptonote::generate_genesis_block(
          bl,
          cryptonote::get_config(cryptonote::MAINNET).GENESIS_TX,
          cryptonote::get_config(cryptonote::MAINNET).GENESIS_NONCE))
    {
      err = "generate_genesis_block failed";
      return false;
    }
    crypto::hash genesis_id{};
    if (!cryptonote::get_block_hash(bl, genesis_id))
    {
      err = "get_block_hash(genesis) failed";
      return false;
    }
    const cryptonote::blobdata blob = cryptonote::get_block_hashing_blob(bl);

    out.label = "genesis";
    out.is_kat = false;
    std::memcpy(out.seed.data(), genesis_id.data, 32);
    out.blob.assign(blob.begin(), blob.end());
    return true;
  }
} // namespace

// Build the per-mode corpus under a single seed. `mode` is "genesis" or
// "canonical"; on success every returned case shares `seed` (one dataset).
bool build_corpus(const std::string &mode, Hash32 &seed,
                  std::vector<Case> &cases, std::string &err)
{
  if (mode == "genesis")
  {
    Case g;
    if (!genesis_case(g, err))
      return false;
    seed = g.seed;
    cases.push_back(std::move(g));
    cases.push_back(Case{"genesis_seed/blob76", seed, pattern(76), false});
    return true;
  }
  if (mode == "canonical")
  {
    for (size_t i = 0; i < seed.size(); ++i)
      seed[i] = static_cast<uint8_t>(i + 1);
    cases.push_back(Case{"canonical/kat", seed, ascii_bytes(kKatBlobAscii), true});
    cases.push_back(Case{"canonical/blob200", seed, pattern(200), false});
    return true;
  }
  err = "unknown mode '" + mode + "' (expected 'genesis' or 'canonical')";
  return false;
}

int run(const std::string &mode)
{
  std::printf(
    "RandomX v2 full-dataset (C) vs light-cache (Rust) parity gate [%s]\n"
    "  pin: external/randomx-v2 @ aaafe71  (RANDOMX_V2_PHASE3_PLAN.md §7)\n"
    "  NOTE: allocates one ~2 080 MiB dataset for this run.\n\n",
    mode.c_str());

  Hash32 seed{};
  std::vector<Case> cases;
  {
    std::string err;
    if (!build_corpus(mode, seed, cases, err))
    {
      std::fprintf(stderr, "FATAL: %s\n", err.c_str());
      return EXIT_FAILURE;
    }
  }

  std::printf("seed %s : building full dataset ...\n",
              to_hex(seed.data(), seed.size()).c_str());
  std::fflush(stdout);

  CFullVm vm;
  {
    std::string err;
    if (!build_c_full(seed, vm, err))
    {
      std::fprintf(stderr, "FATAL: %s\n", err.c_str());
      return EXIT_FAILURE;
    }
  }

  unsigned mismatches = 0;
  unsigned kat_armed = 0;

  for (const Case &c : cases)
  {
    Hash32 cfull{};
    Hash32 rust{};
    c_full_hash(vm.vm, c.blob, cfull);
    if (!rust_light_hash(c.seed, c.blob, rust))
    {
      std::fprintf(stderr, "FATAL: shekyl_pow_randomx_v2_hash failed for %s\n",
                   c.label.c_str());
      return EXIT_FAILURE;
    }

    const bool match = (cfull == rust);
    std::printf("  [%-20s] C-full=%s rust-light=%s  %s\n",
                c.label.c_str(),
                to_hex(cfull.data(), 32).c_str(),
                to_hex(rust.data(), 32).c_str(),
                match ? "OK" : "*** MISMATCH ***");
    if (!match)
      ++mismatches;

    if (c.is_kat)
    {
      const std::string frozen = kFrozenKatHashHex;
      const std::string got = to_hex(cfull.data(), 32);
      if (frozen.empty())
      {
        std::printf("  [kat] CAPTURE MODE: paste into kFrozenKatHashHex: %s\n",
                    got.c_str());
      }
      else if (got != frozen)
      {
        std::fprintf(stderr,
                     "  [kat] *** FROZEN KAT MISMATCH *** expected %s got %s\n",
                     frozen.c_str(), got.c_str());
        ++mismatches;
      }
      else
      {
        ++kat_armed;
        std::printf("  [kat] frozen regression anchor OK\n");
      }
    }
  }

  std::printf("\n");
  if (mismatches != 0)
  {
    std::fprintf(stderr,
      "HALT-ON-RED (RANDOMX_V2_PHASE3_PLAN.md §7.3): %u mismatch(es) [%s].\n"
      "C full-dataset and Rust light-cache diverge at pin aaafe71. This is\n"
      "NOT a test bug: it means the light-only Rust verifier cannot validate\n"
      "full-dataset-mined blocks. Halt the cutover and escalate.\n",
      mismatches, mode.c_str());
    return EXIT_FAILURE;
  }

  std::printf("PASS [%s]: C full-dataset == Rust light-cache across the corpus%s\n",
              mode.c_str(),
              kat_armed ? " (frozen KAT armed)"
                        : (mode == "canonical"
                             ? " (frozen KAT in CAPTURE MODE - paste hash to arm)"
                             : ""));
  return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
  // Unbuffered stdout: the run's result lines must survive the unconditional
  // process-teardown abort described below, so they are never lost to a
  // buffer that the abort skips flushing.
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  // One dataset per process (see file header). The seed is selected by mode
  // so a single ~2 080 MiB dataset is allocated per invocation; ctest runs
  // the two modes as separate processes.
  const std::string mode = (argc > 1) ? argv[1] : "genesis";
  const int rc = run(mode);

  // Exit via _Exit, bypassing C++ static destructors. librandomx's global
  // `SuperscalarInstructionInfo` objects (superscalar.cpp) double-free their
  // `std::vector<MacroOp>` members when the library is unloaded at process
  // exit (confirmed by a gdb backtrace through `_dl_fini` ->
  // `__do_global_dtors_aux` -> `~SuperscalarInstructionInfo`). That teardown
  // abort is independent of hash computation — the parity result above is
  // already decided and printed — but left unhandled it would mask the real
  // pass/fail behind SIGABRT (exit 134) and break the ctest verdict. The
  // upstream teardown double-free is tracked in `docs/FOLLOWUPS.md`.
  std::fflush(stdout);
  std::fflush(stderr);
  std::_Exit(rc);
}
