// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Cross-language pin for the PRUNABLE DIGEST, on a body of every transaction
// class -- the C++ leg of shekyl-wire's `prunable_digest_parity.rs`.
//
// The prunable digest has one definition, in Rust (shekyl-wire
// `prunable_hash_of`). `calculate_transaction_prunable_hash` owns no hash: it
// finds the prunable range -- the bytes after `unprunable_size` -- and hands
// it over (shekyl_tx_prunable_hash). So what this leg can still get wrong,
// and what it pins, is WHICH BYTES C++ takes the range to be, and that
// differs by class: a coinbase has none, a serve-credit transaction's is pass
// records and no proofs, a bond post's and an emission claim's follow
// different inputs.
//
// The pin (`prunable_digest_parity_v1.json`) is authored by shekyl-wire from
// its own parse of each body. This leg parses the same bytes with the C++
// production parser and requires `get_transaction_prunable_hash` to return
// the pinned value both ways it can be asked: with the blob in hand, and with
// only the parsed transaction, which serializes it again to find the range.
//
// The bodies are the daemon-accepted transactions of
// `pqc_signing_preimage_v1.json` (taken from that fixture by name, not copied
// into this one) and one coinbase the parity fixture carries itself.

#include "gtest/gtest.h"

#include <fstream>
#include <map>
#include <set>
#include <string>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "string_tools.h"

#ifndef PRUNABLE_DIGEST_PARITY_FIXTURE_PATH
#define PRUNABLE_DIGEST_PARITY_FIXTURE_PATH \
  "rust/shekyl-wire/tests/fixtures/prunable_digest_parity_v1.json"
#endif
#ifndef PQC_SIGNING_PREIMAGE_FIXTURE_PATH
#define PQC_SIGNING_PREIMAGE_FIXTURE_PATH \
  "rust/shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json"
#endif

using namespace cryptonote;

namespace {

rapidjson::Document load_json(const char* path)
{
  std::ifstream ifs(path);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing fixture at ") + path);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.IsObject() || !doc.HasMember("transactions")
      || !doc["transactions"].IsArray())
    throw std::runtime_error(std::string("invalid fixture at ") + path);
  return doc;
}

// The signing-preimage fixture's bodies, by name.
std::map<std::string, std::string> bodies_by_name()
{
  const rapidjson::Document doc = load_json(PQC_SIGNING_PREIMAGE_FIXTURE_PATH);
  std::map<std::string, std::string> bodies;
  for (const auto& tx : doc["transactions"].GetArray())
    bodies.emplace(tx["name"].GetString(), tx["tx_hex"].GetString());
  return bodies;
}

} // namespace

TEST(prunable_digest_parity, every_class_matches_the_rust_pin_from_the_blob_and_from_the_struct)
{
  const rapidjson::Document pin = load_json(PRUNABLE_DIGEST_PARITY_FIXTURE_PATH);
  const std::map<std::string, std::string> bodies = bodies_by_name();

  std::set<std::string> classes;
  size_t checked = 0;
  for (const auto& entry : pin["transactions"].GetArray())
  {
    const std::string name = entry["name"].GetString();
    SCOPED_TRACE(name);

    // The bytes: the entry's own, or the signing-preimage fixture's.
    std::string tx_hex;
    if (entry.HasMember("tx_hex"))
      tx_hex = entry["tx_hex"].GetString();
    else
    {
      const auto body = bodies.find(name);
      ASSERT_NE(body, bodies.end()) << "the pin names a body the other fixture does not carry";
      tx_hex = body->second;
    }
    blobdata blob;
    ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(tx_hex, blob));

    transaction parsed;
    ASSERT_TRUE(parse_and_validate_tx_from_blob(blob, parsed))
        << "C++ cannot parse a body the pin was authored from";

    const std::string pinned = entry["prunable_hash_hex"].GetString();

    // With the blob in hand: the range is the blob's own tail.
    crypto::hash from_blob = crypto::null_hash;
    const blobdata_ref blob_ref(blob);
    ASSERT_TRUE(calculate_transaction_prunable_hash(parsed, &blob_ref, from_blob));
    EXPECT_EQ(epee::string_tools::pod_to_hex(from_blob), pinned)
        << "the range C++ cuts from the blob is not the region Rust hashed";

    // With only the transaction: it is serialized again to find the range.
    crypto::hash from_struct = crypto::null_hash;
    ASSERT_TRUE(calculate_transaction_prunable_hash(parsed, nullptr, from_struct));
    EXPECT_EQ(epee::string_tools::pod_to_hex(from_struct), pinned)
        << "a fresh serialization gives a different prunable range";

    // The caching entry point returns the same value.
    EXPECT_EQ(epee::string_tools::pod_to_hex(get_transaction_prunable_hash(parsed, &blob_ref)), pinned);

    // A coinbase has no prunable region: the digest of nothing, never null.
    if (std::string(entry["class"].GetString()) == "coinbase")
    {
      EXPECT_EQ(static_cast<size_t>(parsed.unprunable_size.load()), blob.size());
      EXPECT_NE(from_blob, crypto::null_hash);
    }

    classes.insert(entry["class"].GetString());
    ++checked;
  }

  // Rule 47: the subject, asserted. An empty or shortened pin must not pass.
  EXPECT_EQ(checked, 9u);
  const std::set<std::string> every_class = {"bond-post", "coinbase", "emission", "serve-credit-only", "spend"};
  EXPECT_EQ(classes, every_class) << "a transaction class has no pinned prunable digest";
}

// A pruned body has no prunable range to hand over, and is refused rather
// than answered with the digest of nothing -- which is a coinbase's digest,
// and would be a wrong `txs_prunable_hash` row for a spend.
TEST(prunable_digest_parity, a_pruned_body_has_no_prunable_digest_here)
{
  const std::map<std::string, std::string> bodies = bodies_by_name();
  const auto body = bodies.find("spend-1in-2out");
  ASSERT_NE(body, bodies.end());
  blobdata blob;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(body->second, blob));
  transaction full;
  ASSERT_TRUE(parse_and_validate_tx_from_blob(blob, full));

  // The pruned form of the same body, through the production pruned parser.
  const blobdata pruned_blob = blob.substr(0, full.unprunable_size.load());
  transaction pruned;
  ASSERT_TRUE(parse_and_validate_tx_base_from_blob(blobdata_ref(pruned_blob), pruned));
  ASSERT_TRUE(pruned.pruned);

  crypto::hash refused = crypto::null_hash;
  EXPECT_FALSE(calculate_transaction_prunable_hash(pruned, nullptr, refused));
  const blobdata_ref pruned_ref(pruned_blob);
  EXPECT_FALSE(calculate_transaction_prunable_hash(pruned, &pruned_ref, refused));
}
