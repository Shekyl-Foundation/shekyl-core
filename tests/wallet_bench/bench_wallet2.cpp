// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

/// @file bench_wallet2.cpp
/// @brief Google Benchmark harness capturing the wallet2 C++ baseline for
///        commit 1 of docs/MID_REWIRE_HARDENING.md.
///
/// Three hot paths are measured:
///
///   - BM_open_cold        : end-to-end wallet open from on-disk fixtures,
///                           dominated by Argon2id in store_keys.
///   - BM_balance_compute  : balance(0, strict) over N synthetic transfers.
///   - BM_cache_roundtrip  : get_cache_file_data + binary_archive serialize
///                           of a cache with N transfers, paired with
///                           load_wallet_cache deserialize.
///
/// The two remaining paths from the Five (`scan_block_K`,
/// `transfer_e2e_1in_2out`) are Rust-only in commit 3.2; see
/// docs/MID_REWIRE_HARDENING.md §3.1 for the rationale (daemon-coupled
/// tree state that wallet2 has no hermetic provisioning for).

#include "bench_fixtures.h"

#include "wallet/wallet2.h"

#include <benchmark/benchmark.h>

#include <filesystem>
#include <string>

namespace {

// ---------------------------------------------------------------------------
// BM_open_cold
//
// Intent: end-to-end open of a wallet from its on-disk fixture. The
// dominant cost should be Argon2id inside load_keys -> decrypt, plus the
// filesystem read of the .keys + cache files. "Cold open" from the user's
// perspective is wall-clock time between double-click and usable wallet.
//
// Status on this tree: BLOCKED by a pre-existing wallet2 regression where
// a freshly generated wallet (`wallet2::generate` or `generate("", pwd)` +
// `store_to`) does not round-trip through `wallet2::load`: the final
// `hwdev.verify_keys(spend_secret, spend_public)` inside
// `load_keys_buf` returns false and throws
// `tools::error::wallet_files_doesnt_correspond`. This is reproduced by
// the already-failing unit test `wallet_storage.store_to_mem2file` in
// tests/unit_tests/wallet_storage.cpp. Root-causing that regression is
// explicitly out of scope for commit 1 of the hardening pass (see
// docs/MID_REWIRE_HARDENING.md §3.1): the wallet2 keys pipeline is the
// subject of commits 2l / 2m-keys, and any fix lands there.
//
// This benchmark therefore SkipWithError()s at runtime. The scaffolding
// stays in tree so that once wallet2::generate/load is either fixed or
// replaced by the Rust WalletStateStore, un-skipping is a one-line change.
// ---------------------------------------------------------------------------

void BM_open_cold(benchmark::State& state)
{
  state.SkipWithError(
      "wallet2 generate/store_to/load round-trip is broken on this tree: "
      "load_keys_buf's final verify_keys(spend_secret, spend_public) fails "
      "and throws wallet_files_doesnt_correspond. Reproduced by the "
      "already-failing unit test wallet_storage.store_to_mem2file. Fix is "
      "scoped to hardening-pass commits 2l / 2m-keys; see "
      "docs/MID_REWIRE_HARDENING.md §3.1 and "
      "docs/benchmarks/wallet2_baseline_v0.manifest.md 'Known gaps'.");
}
BENCHMARK(BM_open_cold)->Unit(benchmark::kMillisecond)->UseRealTime();

// ---------------------------------------------------------------------------
// BM_balance_compute
//
// Measures: wallet2::balance(0, strict=true) over N synthetic transfers.
// No disk I/O; the wallet is constructed per-iteration but transfers are
// stuffed via wallet_accessor_test, which bypasses scan-time work.
//
// The benchmark is Argn-indexed on N; Google Benchmark treats each
// argument as a separate sub-benchmark, producing cost-per-transfer rows
// in the output JSON.
// ---------------------------------------------------------------------------

void BM_balance_compute(benchmark::State& state)
{
  const auto n = static_cast<std::size_t>(state.range(0));

  tools::wallet2 w;
  shekyl_bench::populate_synthetic_transfers(w, n, /*chain_tip_height=*/1'000'000ULL);

  std::uint64_t sink = 0;
  for (auto _ : state)
  {
    const std::uint64_t bal = w.balance(/*subaddr_index_major=*/0, /*strict=*/true);
    sink ^= bal;
    benchmark::DoNotOptimize(sink);
  }

  state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(n));
  state.counters["per_transfer_ns"] =
      benchmark::Counter(static_cast<double>(n),
                         benchmark::Counter::kIsIterationInvariantRate |
                             benchmark::Counter::kInvert);
  state.counters["transfers"] = static_cast<double>(n);
}
BENCHMARK(BM_balance_compute)
    ->Arg(100)
    ->Arg(1000)
    ->Arg(10000)
    ->Unit(benchmark::kMicrosecond)
    ->UseRealTime();

// ---------------------------------------------------------------------------
// BM_cache_roundtrip
//
// Intent: get_cache_file_data (inner serialize of m_transfers + XChaCha20
// encrypt) + binary_archive serialize of the encrypted blob +
// load_wallet_cache (archive parse + XChaCha20 decrypt + inner
// deserialize) on a wallet holding N transfers.
//
// Status: BLOCKED by the same wallet2 regression as BM_open_cold —
// `get_cache_file_data()` requires a wallet that was loaded via
// `wallet2::load`, and that path throws `wallet_files_doesnt_correspond`
// on freshly generated fixtures. The alternative of writing a raw cache
// blob bypasses the real wallet2 code path and would degrade into a
// measurement of Boost serialization framing only, which is not a useful
// baseline for the format-layer regression canary. SkipWithError keeps
// the scaffolding discoverable; the fix ships with commits 2l / 2m-cache.
// ---------------------------------------------------------------------------

void BM_cache_roundtrip(benchmark::State& state)
{
  const auto n = static_cast<std::size_t>(state.range(0));
  state.counters["transfers"] = static_cast<double>(n);
  state.SkipWithError(
      "depends on wallet2::load round-trip, which is broken on this tree "
      "(see BM_open_cold skip message and wallet_storage.store_to_mem2file). "
      "Re-enables with hardening-pass commits 2l / 2m-cache.");
}
BENCHMARK(BM_cache_roundtrip)
    ->Arg(1000)
    ->Arg(10000)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

}  // namespace

BENCHMARK_MAIN();
