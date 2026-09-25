// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The C++ leg of the per-input PQC signing-preimage KAT
// (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1; the Rust leg is
// `rust/shekyl-wire/tests/pqc_signing_preimage_kat.rs`).
//
// This file exists for the window in which the C++ still assembles the
// preimage (`get_transaction_signed_payload`, `tx_pqc_verify.cpp`) and the
// Rust derivation (`Transaction::pqc_signing_payload_hashes`) is being made
// the one of record. Two modes:
//
// - **Capture** (`SHEKYL_CAPTURE_PQC_PREIMAGE_KAT` set): over the fixture's
//   transactions — eight daemon-accepted bodies the Rust leg's emitter chose
//   for the shapes a divergence could hide in (one, two and six inputs, the
//   bond post's and the emission's mixed archival arms, the serve-credit form
//   with no preimage) — write every input's payload and signed hash into the
//   fixture as the specification's output for those bytes. Run once, before
//   the assembly is deleted. Fails loudly afterwards so a capture run never
//   reads as green (rule 47).
// - **Assert** (default): the C++ assembly reproduces the fixture, input by
//   input. This is the byte-identity gate of E6 slice 6 commit 7's cutover,
//   and it is deleted with the assembly it holds — the fixture and the Rust
//   leg are what survive, as the definition of the preimage rather than a
//   comparison against a program nobody can run.

#include "gtest/gtest.h"

#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/tx_pqc_verify.h"
#include "string_tools.h"
#include "version.h"

#ifndef PQC_SIGNING_PREIMAGE_KAT_FIXTURE_PATH
#define PQC_SIGNING_PREIMAGE_KAT_FIXTURE_PATH \
  "rust/shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json"
#endif

using namespace cryptonote;

namespace {

rapidjson::Document load_fixture()
{
  std::ifstream ifs(PQC_SIGNING_PREIMAGE_KAT_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing preimage fixture at ") + PQC_SIGNING_PREIMAGE_KAT_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.IsObject() || !doc.HasMember("transactions") || !doc["transactions"].IsArray())
    throw std::runtime_error("invalid preimage fixture");
  return doc;
}

// Every input's payload — the §1.1 composition the C++ assembles — and its
// keccak256. A body with no per-input authentication yields none: the
// assembler refuses every index, and "no preimage" is the recorded answer.
struct Preimages {
  std::vector<std::string> payloads;
  std::vector<crypto::hash> hashes;
};

Preimages assemble(const transaction& tx)
{
  Preimages out;
  for (size_t i = 0; i < tx.vin.size(); ++i)
  {
    std::string payload;
    if (!get_transaction_signed_payload(tx, i, payload))
      break;
    crypto::hash h;
    get_blob_hash(payload, h);
    out.payloads.push_back(std::move(payload));
    out.hashes.push_back(h);
  }
  return out;
}

transaction parse(const std::string& tx_hex)
{
  blobdata blob;
  if (!epee::string_tools::parse_hexstr_to_binbuff(tx_hex, blob))
    throw std::runtime_error("fixture tx_hex is not hex");
  transaction tx;
  if (!parse_and_validate_tx_from_blob(blob, tx))
    throw std::runtime_error("fixture transaction does not parse");
  return tx;
}

} // namespace

TEST(pqc_signing_preimage_kat, the_assembly_reproduces_the_specifications_output_for_every_input)
{
  rapidjson::Document doc = load_fixture();
  auto& transactions = doc["transactions"];
  ASSERT_GT(transactions.Size(), 0u) << "an empty fixture asserts nothing (rule 47)";

  if (std::getenv("SHEKYL_CAPTURE_PQC_PREIMAGE_KAT"))
  {
    auto& alloc = doc.GetAllocator();
    for (auto& entry : transactions.GetArray())
    {
      const transaction tx = parse(entry["tx_hex"].GetString());
      const Preimages got = assemble(tx);
      rapidjson::Value payloads(rapidjson::kArrayType);
      rapidjson::Value hashes(rapidjson::kArrayType);
      for (size_t i = 0; i < got.payloads.size(); ++i)
      {
        const std::string p = epee::string_tools::buff_to_hex_nodelimer(got.payloads[i]);
        const std::string h = epee::string_tools::pod_to_hex(got.hashes[i]);
        payloads.PushBack(rapidjson::Value(p.c_str(), alloc), alloc);
        hashes.PushBack(rapidjson::Value(h.c_str(), alloc), alloc);
      }
      entry["payloads_hex"] = payloads;
      entry["signed_hashes_hex"] = hashes;
    }
    const std::string captured_by = std::string("shekyld ") + SHEKYL_VERSION_FULL +
      " get_transaction_signed_payload (tx_pqc_verify.cpp), the C++ assembly, before its deletion";
    doc["captured_by"] = rapidjson::Value(captured_by.c_str(), alloc);

    std::ofstream out(PQC_SIGNING_PREIMAGE_KAT_FIXTURE_PATH, std::ios::trunc);
    ASSERT_TRUE(out.good()) << "cannot write " << PQC_SIGNING_PREIMAGE_KAT_FIXTURE_PATH;
    rapidjson::OStreamWrapper wrapper(out);
    rapidjson::PrettyWriter<rapidjson::OStreamWrapper> writer(wrapper);
    doc.Accept(writer);
    out << '\n';
    FAIL() << "SHEKYL_CAPTURE_PQC_PREIMAGE_KAT set: payloads written to "
           << PQC_SIGNING_PREIMAGE_KAT_FIXTURE_PATH << "; re-run without it to assert";
  }

  ASSERT_TRUE(doc.HasMember("captured_by") && doc["captured_by"].GetStringLength() > 0)
    << "the fixture has not been captured";
  size_t with_preimage = 0;
  size_t without = 0;
  for (const auto& entry : transactions.GetArray())
  {
    const std::string name = entry["name"].GetString();
    SCOPED_TRACE(name);
    const transaction tx = parse(entry["tx_hex"].GetString());
    const Preimages got = assemble(tx);
    const auto& payloads = entry["payloads_hex"];
    const auto& hashes = entry["signed_hashes_hex"];
    ASSERT_EQ(got.payloads.size(), payloads.Size()) << "payload count";
    ASSERT_EQ(got.hashes.size(), hashes.Size()) << "hash count";
    for (rapidjson::SizeType i = 0; i < payloads.Size(); ++i)
    {
      EXPECT_EQ(epee::string_tools::buff_to_hex_nodelimer(got.payloads[i]), std::string(payloads[i].GetString()))
        << "input " << i << ": payload bytes";
      EXPECT_EQ(epee::string_tools::pod_to_hex(got.hashes[i]), std::string(hashes[i].GetString()))
        << "input " << i << ": signed hash";
    }
    (got.payloads.empty() ? without : with_preimage) += 1;
  }
  EXPECT_GE(with_preimage, 7u) << "the spend, bond-post and emission shapes carry preimages";
  EXPECT_EQ(without, 1u) << "the serve-credit form, and only it, has none";
}
