// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Measurement harness: epee's NOTIFY_NEW_TRANSACTIONS encode -> one file per
// shape, so the comparison is `cmp` on raw bytes rather than eyeballed hex.
#include <cstdio>
#include <string>
#include <vector>
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "span.h"

static std::string dir;

static std::string blob(size_t n, char seed)
{ std::string s(n, seed); for (size_t i = 0; i < n; ++i) s[i] = char('a' + ((i + seed) % 26)); return s; }

static void emit(const char* label, const cryptonote::NOTIFY_NEW_TRANSACTIONS::request& r)
{
  epee::byte_slice buf;
  if (!epee::serialization::store_t_to_binary(r, buf)) { std::printf("%s FAILED\n", label); return; }
  const std::string path = dir + "/" + label + ".bin";
  std::FILE* f = std::fopen(path.c_str(), "wb");
  const auto sp = epee::to_span(buf);
  std::fwrite(sp.data(), 1, sp.size(), f);
  std::fclose(f);
  std::printf("%-16s %zu bytes\n", label, sp.size());
}

int main(int argc, char** argv)
{
  dir = argv[1];
  { cryptonote::NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back("tx1"); r.dandelionpp_fluff = false; emit("carrier_shape", r); }
  { cryptonote::NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back("tx1"); r.dandelionpp_fluff = true; emit("fluff_default", r); }
  { cryptonote::NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back("tx1"); r._ = std::string(8, ' '); r.dandelionpp_fluff = false; emit("padded_8sp", r); }
  { cryptonote::NOTIFY_NEW_TRANSACTIONS::request r{};
    r.dandelionpp_fluff = false; emit("empty_txs", r); }
  // 2-byte varint width: realistic relay — 3 blobs ~1500B, `_` ~900 spaces.
  { cryptonote::NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back(blob(1500,1)); r.txs.push_back(blob(1487,2)); r.txs.push_back(blob(1613,3));
    r._ = std::string(900, ' '); r.dandelionpp_fluff = true; emit("realistic_2byte", r); }
  // 4-byte varint width: a blob past 16383.
  { cryptonote::NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back(blob(20000,4)); r._ = std::string(16400, ' '); r.dandelionpp_fluff = false;
    emit("wide_4byte", r); }
  // boundary: exactly 63 / 64 bytes straddles the 1->2 byte varint mark.
  { cryptonote::NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back(blob(63,5)); r._ = std::string(64, ' '); r.dandelionpp_fluff = true;
    emit("boundary_63_64", r); }
  return 0;
}
