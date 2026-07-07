// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// @file randomx_v2_miner_kat.cpp
/// @brief Separate-process, miner-shaped full-dataset KAT capture/check —
///        the discharge of the Phase 3a "in-process-proxy" KAT caveat
///        (RANDOMX_V2_PHASE3_PLAN.md §7.2 #3).
///
/// The parity harness's frozen `kFrozenKatHashHex` was captured by the
/// harness's own in-process full-dataset computation, which makes the
/// anchor's provenance self-referential: the code that asserts the pin is
/// the code that produced it. This tool closes that gap. It is a separate
/// process that consumes the RandomX v2 C library exactly as a miner does —
/// `randomx_get_flags() | FULL_MEM | V2`, cache -> dataset (multi-threaded
/// disjoint-range init, `benchmark.cpp` shape) -> VM -> hash — and shares
/// none of the harness's comparison plumbing, none of the Rust FFI, and
/// none of the daemon's consensus code (its only link dependency is
/// `shekyl_randomx_v2` itself). If this independent computation and the
/// harness's in-process one ever disagree on the same `(seed, blob)`, one
/// of them is not computing what a miner computes.
///
/// Inputs come from argv so the ctest registration in `CMakeLists.txt` is
/// the single visible cross-reference to the harness's constants:
///
///   randomx-v2-miner-kat <blob-ascii> [expected-hash-hex]
///
/// `expected-hash-hex` must be exactly 64 hex characters (either case; no
/// 0x prefix, no whitespace) — anything else is a format error, rejected
/// up front so it can never surface as a spurious KAT mismatch. The seed
/// is the canonical-mode seed `0x01..0x20` (the seed under which
/// `kFrozenKatHashHex` is frozen). With `expected-hash-hex` the tool exits
/// nonzero on mismatch; without it, it prints the computed hash (capture
/// mode, for re-freezing after an intentional pin change).
///
/// Exits via `std::_Exit` for the same reason as the parity harness: the
/// vendored library's static-destructor double-free at process teardown
/// (recorded benign-at-teardown, won't-fix; see the parity harness header)
/// must not mask the verdict behind SIGABRT.

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <randomx.h>

#include "full_dataset_init.h"

namespace
{
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

  // Strict expected-hash validation: exactly 64 hex chars, normalized to
  // lowercase for the compare. Deliberately strict rather than lenient —
  // no 0x prefix, no whitespace stripping: a KAT anchor with a formatting
  // surprise should fail HERE with a format error, not surface as a
  // spurious KAT mismatch (or worse, be quietly massaged into matching).
  bool normalize_expected_hex(const std::string &in, std::string &out)
  {
    if (in.size() != 64)
      return false;
    out.clear();
    out.reserve(64);
    for (const char c : in)
    {
      if (!std::isxdigit(static_cast<unsigned char>(c)))
        return false;
      out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return true;
  }
} // namespace

int main(int argc, char **argv)
{
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  if (argc < 2 || argc > 3)
  {
    std::fprintf(stderr, "usage: %s <blob-ascii> [expected-hash-hex]\n", argv[0]);
    std::_Exit(EXIT_FAILURE);
  }
  const char *blob = argv[1];
  const size_t blob_len = std::strlen(blob);
  std::string expected;
  if (argc == 3 && !normalize_expected_hex(argv[2], expected))
  {
    std::fprintf(stderr,
                 "FATAL: expected-hash-hex must be exactly 64 hex characters "
                 "(no 0x prefix, no whitespace); got %zu chars\n",
                 std::strlen(argv[2]));
    std::_Exit(EXIT_FAILURE);
  }

  std::printf(
    "RandomX v2 miner-shaped full-dataset KAT [pin aaafe71]\n"
    "  seed 0x01..0x20, blob %zu bytes\n"
    "  NOTE: allocates one ~2 080 MiB dataset for this run.\n\n",
    blob_len);

  // The canonical-mode seed (0x01..0x20), byte-for-byte the seed under
  // which the parity harness freezes kFrozenKatHashHex.
  std::array<uint8_t, 32> seed{};
  for (size_t i = 0; i < seed.size(); ++i)
    seed[i] = static_cast<uint8_t>(i + 1);

  // Miner flag set: hardware-recommended perf flags + FULL_MEM + V2,
  // exactly as the library's own mining path (src/tests/benchmark.cpp)
  // composes them.
  const randomx_flags flags =
    randomx_get_flags() | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2;

  randomx_cache *cache = randomx_alloc_cache(flags);
  if (!cache)
  {
    std::fprintf(stderr, "FATAL: randomx_alloc_cache failed\n");
    std::_Exit(EXIT_FAILURE);
  }
  randomx_init_cache(cache, seed.data(), seed.size());

  randomx_dataset *dataset = randomx_alloc_dataset(flags);
  if (!dataset)
  {
    std::fprintf(stderr, "FATAL: randomx_alloc_dataset failed (~2 080 MiB)\n");
    std::_Exit(EXIT_FAILURE);
  }
  std::string init_err;
  if (!shekyl_parity::init_full_dataset(dataset, cache, init_err))
  {
    std::fprintf(stderr, "FATAL: %s\n", init_err.c_str());
    std::_Exit(EXIT_FAILURE);
  }
  randomx_release_cache(cache);

  randomx_vm *vm = randomx_create_vm(flags, nullptr, dataset);
  if (!vm)
  {
    std::fprintf(stderr, "FATAL: randomx_create_vm(FULL_MEM|V2) failed\n");
    std::_Exit(EXIT_FAILURE);
  }

  std::array<uint8_t, 32> hash{};
  randomx_calculate_hash(vm, blob, blob_len, hash.data());

  const std::string got = to_hex(hash.data(), hash.size());
  std::printf("miner-KAT hash: %s\n", got.c_str());

  int rc = EXIT_SUCCESS;
  if (expected.empty())
  {
    std::printf("(capture mode: no expected hash supplied)\n");
  }
  else if (got != expected)
  {
    std::fprintf(stderr,
                 "*** MINER-KAT MISMATCH *** expected %s\n"
                 "The independent miner-shaped computation disagrees with the\n"
                 "frozen anchor: library, flags, or pin drifted.\n",
                 expected.c_str());
    rc = EXIT_FAILURE;
  }
  else
  {
    std::printf("PASS: miner-shaped full-dataset computation matches the frozen KAT\n");
  }

  std::fflush(stdout);
  std::fflush(stderr);
  std::_Exit(rc);
}
