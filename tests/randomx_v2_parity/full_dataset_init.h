// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// @file full_dataset_init.h
/// @brief Multi-threaded RandomX full-dataset initialization, shared by
///        the Phase 3a parity harness (`randomx_v2_full_parity.cpp`) and
///        the miner-KAT capture tool (`randomx_v2_miner_kat.cpp`).
///
/// Mirrors the library's own mining path (`src/tests/benchmark.cpp`,
/// `initThreadCount > 1` branch): the item range is split into disjoint
/// contiguous chunks, one `randomx_init_dataset` call per thread.
/// Dataset item content is a pure function of the cache and the item
/// index, so the split does not affect the resulting bytes — only the
/// wall clock. The parity gate originally used the single-threaded
/// fill for simplicity (one dataset per run); with the corpus-widened
/// gate building up to 32+ datasets per cron run, the ~NPROC× speedup
/// is what keeps the sweep inside a CI job budget.

#pragma once

#include <exception>
#include <string>
#include <thread>
#include <vector>

#include <randomx.h>

namespace shekyl_parity
{
  // Initialize `dataset` from `cache` across hardware_concurrency()
  // threads (disjoint item ranges; deterministic result).
  //
  // Returns false (with `err` set) instead of throwing: both consumers
  // (the parity harness and the miner-KAT tool) route failures through a
  // printed FATAL + `std::_Exit` so nothing can mask the verdict behind
  // an abort — an exception escaping to an uncaught `main` would
  // `std::terminate` (SIGABRT), exactly the masking the `_Exit` strategy
  // exists to avoid. The only realistic throw here is a `std::thread`
  // constructor failing on resource exhaustion.
  inline bool init_full_dataset(randomx_dataset *dataset, randomx_cache *cache,
                                std::string &err)
  {
    const unsigned long item_count = randomx_dataset_item_count();
    unsigned long threads = std::thread::hardware_concurrency();
    if (threads == 0)
      threads = 1;
    if (threads > item_count)
      threads = item_count;

    std::vector<std::thread> workers;
    workers.reserve(threads);
    unsigned long start = 0;
    try
    {
      for (unsigned long t = 0; t < threads; ++t)
      {
        const unsigned long count = item_count / threads + (t < item_count % threads ? 1 : 0);
        workers.emplace_back([dataset, cache, start, count] {
          randomx_init_dataset(dataset, cache, start, count);
        });
        start += count;
      }
    }
    catch (const std::exception &e)
    {
      // Already-spawned workers must be joined before returning: a
      // joinable thread's destructor calls std::terminate. Their ranges
      // complete normally; the dataset is simply left partially filled,
      // which is fine — the caller aborts the run.
      for (std::thread &w : workers)
        w.join();
      err = std::string("dataset init thread spawn failed: ") + e.what();
      return false;
    }
    for (std::thread &w : workers)
      w.join();
    return true;
  }
} // namespace shekyl_parity
