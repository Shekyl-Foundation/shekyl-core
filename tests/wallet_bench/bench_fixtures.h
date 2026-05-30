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

#pragma once

/// @file bench_fixtures.h
/// @brief Seeded fixture builders for the wallet2 baseline benchmark harness.
///
/// Purpose: capture wallet2's hot-path performance before the C++ paths are
/// deleted in commit 2m-cache. See docs/MID_REWIRE_HARDENING.md §3.1 for the
/// full rationale and docs/benchmarks/wallet2_baseline_v0.manifest.md for the
/// per-benchmark operation lists.
///
/// All fixtures use a pinned seed (`kBenchSeed`) so two runs produce
/// byte-identical inputs. Nothing here is cryptographically meaningful;
/// transfer_details are assembled with plausible-enough fields to exercise
/// the balance() and cache-serialization paths, not to be spendable.

#include "wallet/wallet2.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

/// Global-namespace friend of `tools::wallet2`. `wallet2.h` declares
/// `friend class ::wallet_accessor_test;` (src/wallet/wallet2.h). This class
/// mirrors the name so the benchmark harness can populate `m_transfers`
/// without dragging in the heavier `tests/core_tests/wallet_tools.h` which
/// transitively pulls chaingen plumbing.
class wallet_accessor_test
{
public:
  static tools::wallet2::transfer_container& get_transfers(tools::wallet2& w)
  {
    return w.m_transfers;
  }

  static std::optional<tools::wallet2::cache_file_data> get_cache_file_data(tools::wallet2& w)
  {
    return w.get_cache_file_data();
  }

  static void load_wallet_cache(tools::wallet2& w, const std::string& cache_buf)
  {
    w.load_wallet_cache(false, cache_buf);
  }
};

namespace shekyl_bench {

/// Pinned RNG seed so every run observes the same synthetic inputs.
/// Two runs on the same machine produce byte-identical transfer vectors;
/// two runs on different machines produce byte-identical transfer vectors.
inline constexpr std::uint64_t kBenchSeed = 0xBEEFF00DCAFEBABEULL;

/// Default password used for on-disk wallet fixtures produced by the harness.
/// Not a secret; the fixtures are throwaway and never carry real funds.
inline constexpr const char* kBenchPassword = "shekyl-wallet-bench-v0";

/// RAII wrapper for a temporary wallet directory. The directory is removed
/// on destruction. Benchmarks that need on-disk state (e.g. `open_cold`)
/// construct one of these, write the fixture inside, and let the destructor
/// clean up at benchmark tear-down.
class TempWalletDir
{
public:
  TempWalletDir();
  ~TempWalletDir();

  TempWalletDir(const TempWalletDir&)            = delete;
  TempWalletDir& operator=(const TempWalletDir&) = delete;

  const std::filesystem::path& path() const noexcept { return m_path; }
  std::string wallet_base() const { return (m_path / "bench_wallet").string(); }

private:
  std::filesystem::path m_path;
};

/// Populate `m_transfers` with `count` synthetic entries.
///
/// The transfers are populated with plausible-enough fields to exercise:
///   - balance() iteration (m_amount, m_spent, m_frozen, m_block_height,
///     m_subaddr_index, m_unlock_time through the tx's unlock_time field);
///   - is_transfer_unlocked() via m_block_height and the tx's unlock_time;
///   - cache serialization (all FIELD(...) members in transfer_details::
///     BEGIN_SERIALIZE_OBJECT()).
///
/// Shape choices:
///   - Half the transfers are spent (m_spent = true), half unspent, so
///     balance() is forced down both branches.
///   - Single-account wallet (subaddr_index.major = 0) to match the common
///     balance(0, strict) query.
///   - Amounts drawn from the seeded RNG, range [1, 2^40].
///   - All transfers placed at heights below a provided `chain_tip` so
///     is_transfer_unlocked is deterministic.
///
/// Postcondition: `w.m_transfers.size() == count`.
void populate_synthetic_transfers(tools::wallet2& w,
                                  std::size_t     count,
                                  std::uint64_t   chain_tip_height);

/// Generate a fresh wallet keypair, call `wallet2::generate()`, then
/// `wallet2::store()` to flush the keys + cache files to disk. The wallet
/// object is returned in the closed state; callers must open it via `load()`
/// to measure the cold path.
///
/// Cache is empty (no transfers) for `open_cold` — that is the representative
/// cold path for a freshly-created or freshly-restored wallet. A
/// `balance_compute_N` benchmark that also round-trips through disk would
/// double-count the cold-open cost, which `open_cold` already owns.
void generate_fresh_wallet_to_disk(const std::string& wallet_base);

/// Serialize a wallet's cache to an in-memory string (binary archive),
/// matching the internal path that wallet2::store() uses for the cache blob.
/// Returns the byte size of the produced archive.
///
/// This is the outbound half of `cache_serialize_roundtrip_N`. The inbound
/// half (`wallet_accessor_test::load_wallet_cache`) is called directly from
/// the benchmark to keep the measurement boundary visible at the call site.
std::size_t serialize_cache_blob(tools::wallet2& w, std::string& out);

}  // namespace shekyl_bench
