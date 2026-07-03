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
/// Corpus (§7.2 #2): each mode exercises exactly one seed in its **own
/// process** (see "one dataset per process" below), selected by `argv[1]`:
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
///   - `corpus <file> <seed_index> <expected_seed_count>`
///                 : one seed group of the Phase 2g nightly random corpus
///                   (32 seeds × 32 blobs, `gen-parity-corpus` v1 file; see
///                   `rust/shekyl-randomx-differential/src/parity_corpus.rs`
///                   for the format). Every case is additionally pinned to
///                   its committed canonical hash
///                   (`CANONICAL_RANDOM_HASHES`), so the run re-checks the
///                   Phase 2g pins under the C **full-dataset** mode — the
///                   mode miners actually run — instead of only the C-light
///                   mode that derived them. `<expected_seed_count>` guards
///                   the ctest registration in `CMakeLists.txt` against a
///                   corpus-sizing change: if the file carries a different
///                   seed count, every registered invocation fails loudly
///                   rather than silently leaving new seeds untested.
///
/// One dataset per process: each ~2 080 MiB dataset is allocated and
/// released in its own process invocation (`genesis` / `canonical` /
/// `corpus <i>`), so peak memory stays at one dataset and a failure is
/// isolated to its seed. ctest drives the modes as separate processes (see
/// this directory's `CMakeLists.txt`). Dataset initialization is
/// multi-threaded over disjoint item ranges (`full_dataset_init.h`,
/// mirroring the library's own `benchmark.cpp` mining path); the item bytes
/// are a pure function of the cache, so threading affects wall clock only.
///
/// Library teardown bug: librandomx's global `SuperscalarInstructionInfo`
/// objects double-free their `std::vector<MacroOp>` members when the shared
/// library is unloaded at process exit (confirmed by a gdb backtrace through
/// `_dl_fini` -> `__do_global_dtors_aux` -> `~SuperscalarInstructionInfo`).
/// This is a teardown-only defect: it fires after the parity result is
/// computed and printed, independent of hash correctness. `main` exits via
/// `std::_Exit` to bypass the broken static destructors so the abort cannot
/// mask the real verdict. Recorded disposition (RandomX v2 test-regime
/// hardening PR-1, 2026-07): **benign-at-teardown, won't-fix** — no consumer
/// of a *result* is affected (the Rust consensus verifier does not link the
/// C library; a long-running miner reaches teardown only at clean shutdown),
/// and patching the vendored fork's static-object lifetime is contortion of
/// a disposable upstream (`10-shekyl-first.mdc`). Reopen only if the
/// double-free is ever observed *before* teardown, where it could corrupt a
/// live result; the gdb evidence above is the citation.
///
/// Halt-on-red (§7.3): a mismatch is **not** a test bug. It is a discovery
/// that the v2 library's light and full modes diverge at the pinned commit
/// `aaafe71`, which would mean the light-only Rust verifier cannot validate
/// full-dataset-mined blocks at all. The disposition is to **halt the
/// cutover and escalate** for an architecture rethink, not to patch this
/// test or proceed to Phase 3b.
///
/// KAT provenance (§7.2 #3): the frozen `kFrozenKatHashHex` below was
/// originally captured from this harness's own in-process full-dataset
/// computation. The in-process-proxy gap is now closed by the sibling
/// miner-KAT capture tool (`randomx_v2_miner_kat.cpp`): a separate process
/// that consumes the C library exactly as a miner does (no FFI, no harness
/// plumbing) recomputes the same `(seed, blob)` under FULL_MEM|V2 and
/// asserts the same frozen hash on every gate run
/// (`randomx_v2_full_parity_miner_kat`).
///
/// Gating: cron gate, not per-PR (a ~2 080 MiB dataset per exercised seed).
/// The `full-parity` job in `.github/workflows/randomx-v2-differential.yml`
/// runs `ctest -L randomx_v2_full_parity_daily` on the daily cron (genesis +
/// canonical + miner-KAT + corpus seeds 0-15) and the full
/// `ctest -L randomx_v2_full_parity` sweep (all 32 corpus seeds — all 1024
/// pins) on the weekly cron. See this directory's `CMakeLists.txt` for the
/// labels and for how the corpus file is generated.

#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <randomx.h>

#include "full_dataset_init.h"
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
  // against the frozen regression hash when one is pinned. `has_pin` entries
  // (corpus mode) assert the C-full hash against the case's committed
  // canonical hash from the Phase 2g pin table (`CANONICAL_RANDOM_HASHES`,
  // carried per-record in the corpus file).
  struct Case
  {
    std::string label;
    Hash32 seed;
    std::vector<uint8_t> blob;
    bool is_kat = false;
    bool has_pin = false;
    Hash32 pin{};
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

    // Multi-threaded dataset initialization (benchmark.cpp's disjoint-range
    // pattern; see full_dataset_init.h). Dataset init dominates this gate's
    // runtime, and the corpus mode builds up to 32 datasets per cron run.
    shekyl_parity::init_full_dataset(out.dataset, out.cache);

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

  // ---- gen-parity-corpus v1 file reader ---------------------------------
  //
  // Format contract:
  // rust/shekyl-randomx-differential/src/parity_corpus.rs (the sole writer).
  // All integers little-endian u32; layout:
  //   [8] magic "SKLPRTY1"
  //   u32 seedhash_count, u32 data_per_seedhash
  //   per seed group: [32] seedhash, then data_per_seedhash records of
  //     { u32 canonical_index, [32] canonical_hash, u32 data_len,
  //       [data_len] data }
  // The reader walks the whole file structurally (so truncation or trailing
  // garbage fails every invocation, not just the last seed's), keeps only
  // the requested group's blobs in memory, and re-derives canonical_index
  // to reject any record shift.

  // Upper bound on a single corpus blob: the generator's R1-D4 ceiling
  // (corpus_random.rs DATA_LEN_BLOCK_TEMPLATE_MAX, an exclusive bound), so
  // any record at or above it indicates a corrupt or foreign file.
  constexpr uint32_t kCorpusMaxDataLen = 600u * 1024u;

  bool read_u32_le(std::ifstream &in, uint32_t &out)
  {
    uint8_t b[4];
    if (!in.read(reinterpret_cast<char *>(b), sizeof(b)))
      return false;
    out = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
          (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
    return true;
  }

  bool load_corpus_group(const std::string &path, uint32_t seed_index,
                         uint32_t expected_seed_count, Hash32 &seed,
                         std::vector<Case> &cases, std::string &err)
  {
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
      err = "cannot open corpus file '" + path +
            "' (generate with: cargo run --release -p "
            "shekyl-randomx-differential --bin gen-parity-corpus -- --out <path>)";
      return false;
    }

    // Physical file size, for the walk-accounts-for-every-byte check at the
    // end. A pure EOF probe is not enough: seekg past EOF on a filebuf
    // succeeds without setting failbit, so a file truncated inside a
    // *skipped* record's data would pass peek()==EOF (verified empirically:
    // 9 bytes cut from the final blob passed every seed<31 invocation).
    in.seekg(0, std::ios::end);
    const std::streamoff file_size = in.tellg();
    if (!in.seekg(0, std::ios::beg))
    {
      err = "cannot determine corpus file size";
      return false;
    }

    char magic[8];
    if (!in.read(magic, sizeof(magic)) || std::memcmp(magic, "SKLPRTY1", 8) != 0)
    {
      err = "bad corpus magic (expected SKLPRTY1; regenerate the file and keep "
            "writer/reader in the same commit on a format change)";
      return false;
    }

    uint32_t seed_count = 0, data_per_seed = 0;
    if (!read_u32_le(in, seed_count) || !read_u32_le(in, data_per_seed))
    {
      err = "truncated corpus header";
      return false;
    }
    if (seed_count != expected_seed_count)
    {
      char buf[160];
      std::snprintf(buf, sizeof(buf),
                    "corpus carries %u seeds but the ctest registration expects %u; "
                    "update tests/randomx_v2_parity/CMakeLists.txt to cover every seed",
                    seed_count, expected_seed_count);
      err = buf;
      return false;
    }
    if (seed_index >= seed_count)
    {
      err = "seed index out of range";
      return false;
    }
    if (data_per_seed == 0)
    {
      err = "corpus declares zero blobs per seed";
      return false;
    }

    for (uint32_t i = 0; i < seed_count; ++i)
    {
      const bool selected = (i == seed_index);
      Hash32 group_seed{};
      if (!in.read(reinterpret_cast<char *>(group_seed.data()), group_seed.size()))
      {
        err = "truncated corpus (seedhash)";
        return false;
      }
      for (uint32_t j = 0; j < data_per_seed; ++j)
      {
        uint32_t canonical_index = 0;
        Hash32 pin{};
        uint32_t data_len = 0;
        if (!read_u32_le(in, canonical_index) ||
            !in.read(reinterpret_cast<char *>(pin.data()), pin.size()) ||
            !read_u32_le(in, data_len))
        {
          err = "truncated corpus (record header)";
          return false;
        }
        if (canonical_index != i * data_per_seed + j)
        {
          err = "corpus record index mismatch (shifted or interleaved records)";
          return false;
        }
        if (data_len >= kCorpusMaxDataLen)
        {
          err = "corpus record exceeds the R1-D4 data-length ceiling";
          return false;
        }
        if (selected)
        {
          Case c;
          char label[48];
          std::snprintf(label, sizeof(label), "corpus/%u (pin %u)", j, canonical_index);
          c.label = label;
          c.seed = group_seed;
          c.blob.resize(data_len);
          if (!in.read(reinterpret_cast<char *>(c.blob.data()), data_len))
          {
            err = "truncated corpus (record data)";
            return false;
          }
          c.has_pin = true;
          c.pin = pin;
          cases.push_back(std::move(c));
        }
        else if (!in.seekg(data_len, std::ios::cur))
        {
          err = "truncated corpus (record data)";
          return false;
        }
      }
      if (selected)
        seed = group_seed;
    }

    // Byte-exact: the walked structure must account for exactly the
    // physical file. tellg > file_size means a skipped record's seekg ran
    // past EOF (truncation the seek itself does not report — see the
    // file_size note above); tellg < file_size means trailing bytes
    // (writer/reader drift).
    const std::streamoff end_pos = in.tellg();
    if (!in || end_pos != file_size)
    {
      err = "corpus structure does not match the physical file size "
            "(truncated file or trailing bytes)";
      return false;
    }
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

int run_cases(const std::string &mode, const Hash32 &seed,
              const std::vector<Case> &cases)
{
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
  unsigned pin_mismatches = 0;
  unsigned kat_armed = 0;

  for (const Case &c : cases)
  {
    // The dataset above was built from `seed`; the Rust leg and the pin
    // are evaluated under `c.seed`. Every mode populates all cases with
    // the one group seed, but nothing else enforces that — and a
    // mis-plumbed seed would surface as HALT-ON-RED, misattributing a
    // harness bug to a consensus-critical light/full divergence.
    if (c.seed != seed)
    {
      std::fprintf(stderr,
                   "FATAL: case %s carries a different seed than the dataset "
                   "(harness seed plumbing bug, NOT a parity divergence)\n",
                   c.label.c_str());
      return EXIT_FAILURE;
    }
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

    if (c.has_pin && cfull != c.pin)
    {
      std::fprintf(stderr,
                   "  [pin] *** CANONICAL PIN MISMATCH *** expected %s got %s\n",
                   to_hex(c.pin.data(), 32).c_str(),
                   to_hex(cfull.data(), 32).c_str());
      ++pin_mismatches;
    }

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
  if (pin_mismatches != 0)
  {
    // Distinct from HALT-ON-RED: C-full and Rust-light AGREE with each
    // other but not with the committed Phase 2g canonical pin. That is not
    // a light/full divergence — it means the library, the corpus stream, or
    // the pin table drifted since the C5a capture (or the corpus file is
    // stale). Investigate the pin-regeneration chain before touching the
    // cutover.
    std::fprintf(stderr,
      "CANONICAL PIN DRIFT: %u pin mismatch(es) [%s] with C-full == Rust-light.\n"
      "The computed hashes no longer match CANONICAL_RANDOM_HASHES. Regenerate\n"
      "the corpus file against the current tree; if the mismatch persists, the\n"
      "substrate changed under the pins — audit before proceeding.\n",
      pin_mismatches, mode.c_str());
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

void print_banner(const std::string &mode)
{
  std::printf(
    "RandomX v2 full-dataset (C) vs light-cache (Rust) parity gate [%s]\n"
    "  pin: external/randomx-v2 @ aaafe71  (RANDOMX_V2_PHASE3_PLAN.md §7)\n"
    "  NOTE: allocates one ~2 080 MiB dataset for this run.\n\n",
    mode.c_str());
}

int run(const std::string &mode)
{
  print_banner(mode);

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
  return run_cases(mode, seed, cases);
}

int run_corpus(const std::string &path, uint32_t seed_index,
               uint32_t expected_seed_count)
{
  char mode[32];
  std::snprintf(mode, sizeof(mode), "corpus seed %u", seed_index);
  print_banner(mode);

  Hash32 seed{};
  std::vector<Case> cases;
  {
    std::string err;
    if (!load_corpus_group(path, seed_index, expected_seed_count, seed, cases, err))
    {
      std::fprintf(stderr, "FATAL: %s\n", err.c_str());
      return EXIT_FAILURE;
    }
  }
  std::printf("loaded %zu pinned case(s) for seed %u from %s\n",
              cases.size(), seed_index, path.c_str());
  return run_cases(mode, seed, cases);
}

int main(int argc, char **argv)
{
  // Unbuffered stdout: the run's result lines must survive the unconditional
  // process-teardown abort described below, so they are never lost to a
  // buffer that the abort skips flushing.
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  // One dataset per process (see file header). The seed is selected by mode
  // so a single ~2 080 MiB dataset is allocated per invocation; ctest runs
  // every mode as a separate process.
  const std::string mode = (argc > 1) ? argv[1] : "genesis";
  int rc = EXIT_FAILURE;
  if (mode == "corpus")
  {
    if (argc != 5)
    {
      std::fprintf(stderr,
                   "usage: %s corpus <file> <seed_index> <expected_seed_count>\n",
                   argv[0]);
    }
    else
    {
      // Strict decimal-u32 parse. strtoul alone is not enough: it accepts
      // "" (returns 0 with end at the terminator), "-1" (wraps to
      // ULONG_MAX without ERANGE), and values above UINT32_MAX that a bare
      // cast would silently truncate into a *valid* index — e.g.
      // 4294967296 → seed 0.
      char *end_index = nullptr;
      char *end_count = nullptr;
      errno = 0;
      const unsigned long seed_index = std::strtoul(argv[3], &end_index, 10);
      const unsigned long seed_count = std::strtoul(argv[4], &end_count, 10);
      const bool digits_only =
        std::isdigit(static_cast<unsigned char>(argv[3][0])) &&
        std::isdigit(static_cast<unsigned char>(argv[4][0])) &&
        end_index && *end_index == '\0' && end_count && *end_count == '\0';
      if (!digits_only || errno == ERANGE ||
          seed_index > UINT32_MAX || seed_count > UINT32_MAX)
        std::fprintf(stderr,
                     "FATAL: corpus arguments must be decimal integers in [0, 2^32)\n");
      else
        rc = run_corpus(argv[2], static_cast<uint32_t>(seed_index),
                        static_cast<uint32_t>(seed_count));
    }
  }
  else
  {
    rc = run(mode);
  }

  // Exit via _Exit, bypassing C++ static destructors. librandomx's global
  // `SuperscalarInstructionInfo` objects (superscalar.cpp) double-free their
  // `std::vector<MacroOp>` members when the library is unloaded at process
  // exit (confirmed by a gdb backtrace through `_dl_fini` ->
  // `__do_global_dtors_aux` -> `~SuperscalarInstructionInfo`). That teardown
  // abort is independent of hash computation — the parity result above is
  // already decided and printed — but left unhandled it would mask the real
  // pass/fail behind SIGABRT (exit 134) and break the ctest verdict. The
  // recorded disposition is benign-at-teardown, won't-fix (see file header).
  std::fflush(stdout);
  std::fflush(stderr);
  std::_Exit(rc);
}
