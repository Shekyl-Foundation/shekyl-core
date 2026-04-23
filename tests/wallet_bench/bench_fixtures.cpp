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

#include "bench_fixtures.h"

#include "cryptonote_basic/cryptonote_basic.h"
#include "serialization/binary_archive.h"
#include "serialization/serialization.h"

#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace shekyl_bench {

namespace {

// Fills a raw 32-byte region with seeded pseudorandom bytes. Used for
// key-image / output-pubkey / mask slots that only need to be unique and
// stable across runs, not cryptographically valid. Security property: none.
void fill_random_bytes(std::mt19937_64& rng, unsigned char* dst, std::size_t n)
{
  for (std::size_t i = 0; i < n; i += 8)
  {
    const std::uint64_t v = rng();
    const std::size_t   r = std::min<std::size_t>(8, n - i);
    std::memcpy(dst + i, &v, r);
  }
}

std::filesystem::path make_unique_temp_dir()
{
  namespace fs = std::filesystem;
  std::error_code ec;
  const fs::path  base = fs::temp_directory_path(ec);
  if (ec)
    throw std::runtime_error("bench: temp_directory_path failed: " + ec.message());

  // Use pid + a rolling counter to avoid collisions between parallel
  // benchmark instances on the same machine.
  static std::atomic<std::uint64_t> counter{0};
  const auto n = counter.fetch_add(1, std::memory_order_relaxed);
  const auto pid =
#ifdef _WIN32
      static_cast<std::uint64_t>(::_getpid());
#else
      static_cast<std::uint64_t>(::getpid());
#endif

  fs::path candidate;
  for (int attempt = 0; attempt < 16; ++attempt)
  {
    std::ostringstream oss;
    oss << "shekyl-wallet-bench-" << pid << "-" << (n + attempt);
    candidate = base / oss.str();
    if (fs::create_directory(candidate, ec))
      return candidate;
    if (ec && ec != std::errc::file_exists)
      throw std::runtime_error("bench: create_directory failed: " + ec.message());
  }
  throw std::runtime_error("bench: could not create unique temp directory after 16 attempts");
}

}  // namespace

TempWalletDir::TempWalletDir() : m_path(make_unique_temp_dir()) {}

TempWalletDir::~TempWalletDir()
{
  std::error_code ec;
  std::filesystem::remove_all(m_path, ec);
  // Best-effort cleanup; a benchmark teardown is not the right place to
  // throw. Stale dirs under /tmp are harmless and get GCed by the OS.
}

void populate_synthetic_transfers(tools::wallet2& w,
                                  std::size_t     count,
                                  std::uint64_t   chain_tip_height)
{
  auto& transfers = wallet_accessor_test::get_transfers(w);
  transfers.clear();
  transfers.reserve(count);

  std::mt19937_64 rng(kBenchSeed);
  // Non-uniform amount distribution: a mix of dust, mid, and large amounts
  // matching roughly what a long-running wallet accumulates. The
  // distribution shape is not cryptographically meaningful; it only needs
  // to keep balance()'s summation path from trivially short-circuiting.
  std::uniform_int_distribution<std::uint64_t> amount_dist(1ULL, (1ULL << 40) - 1);

  for (std::size_t i = 0; i < count; ++i)
  {
    tools::wallet2::transfer_details td;

    td.m_block_height = (chain_tip_height > 0)
                            ? (rng() % chain_tip_height)
                            : static_cast<std::uint64_t>(i);
    td.m_internal_output_index = i % 4;
    td.m_global_output_index   = i;
    // Alternate spent/unspent so balance() exercises both branches of
    // its inner filter.
    td.m_spent         = (i & 1U) != 0;
    td.m_frozen        = false;
    td.m_spent_height  = td.m_spent ? td.m_block_height + 1 : 0;
    td.m_amount        = amount_dist(rng);
    td.m_pk_index      = 0;
    td.m_key_image_known   = true;
    td.m_key_image_request = false;

    // Single account; spread across a handful of minor indices to make
    // subaddress-filter paths non-degenerate.
    td.m_subaddr_index.major = 0;
    td.m_subaddr_index.minor = static_cast<std::uint32_t>(i % 8);

    // Opaque 32-byte slots. Not cryptographically valid; balance() and
    // the cache serialization pass do not dereference them, they only
    // read/write the bytes.
    fill_random_bytes(rng, reinterpret_cast<unsigned char*>(&td.m_key_image), 32);
    fill_random_bytes(rng, reinterpret_cast<unsigned char*>(&td.m_mask),      32);
    fill_random_bytes(rng, reinterpret_cast<unsigned char*>(&td.m_y),         32);
    fill_random_bytes(rng, reinterpret_cast<unsigned char*>(&td.m_k_amount),  32);
    fill_random_bytes(rng, reinterpret_cast<unsigned char*>(&td.m_txid),      32);

    // Staking fields at rest: un-staked output, zeroed watermarks.
    td.m_staked           = false;
    td.m_stake_tier       = 0;
    td.m_stake_lock_until = 0;
    td.m_last_claimed_height = 0;
    td.m_combined_shared_secret_set = false;

    // m_tx and m_uses are default-constructed. transfer_details'
    // serialization macros will emit them as empty vectors / zero hashes,
    // which is sufficient for the cache roundtrip path. balance() does
    // not inspect m_tx.

    transfers.emplace_back(std::move(td));
  }
}

void generate_fresh_wallet_to_disk(const std::string& wallet_base)
{
  // Match the working pattern in tests/unit_tests/wallet_storage.cpp
  // (store_to_mem2file): default-construct wallet2, generate("", password)
  // in-memory, then store_to(path, password). The on-disk `base` + `.keys`
  // pair produced this way round-trips cleanly through load(path, password).
  tools::wallet2 w;
  const epee::wipeable_string password(kBenchPassword);
  (void)w.generate("", password);
  w.store_to(wallet_base, password);
}

std::size_t serialize_cache_blob(tools::wallet2& w, std::string& out)
{
  auto cfd = wallet_accessor_test::get_cache_file_data(w);
  if (!cfd.has_value())
    throw std::runtime_error("bench: get_cache_file_data returned nullopt");

  std::ostringstream   oss;
  binary_archive<true> oar(oss);
  if (!::serialization::serialize(oar, *cfd))
    throw std::runtime_error("bench: cache_file_data serialize failed");
  out = oss.str();
  return out.size();
}

}  // namespace shekyl_bench
