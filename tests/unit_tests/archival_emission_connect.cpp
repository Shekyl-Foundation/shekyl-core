// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// C-1 connect-arm KATs (REWARD_EMISSION_E3_GATING_ROUND.md §9.5 item 7):
// BlockchainDB::add_transaction's txin_archival_reward_emission arm must
// re-extract (P_canonical_id, settlement_epochs) from the opaque blob through
// shekyl_archival_emission_vin_extract and hand them to the single writer
// apply_archival_emission_claim; emission vouts must store as amount-0 RCT
// records with their outPk commitment (the coinbase shape).

#include "gtest/gtest.h"

#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "blockchain_db/testdb.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "fcmp/ct_types.h"
#include "string_tools.h"

#ifndef EMISSION_CONNECT_KAT_FIXTURE_PATH
#define EMISSION_CONNECT_KAT_FIXTURE_PATH "rust/shekyl-archival-retention/tests/fixtures/emission_connect_kat_v1.json"
#endif

using namespace cryptonote;

namespace {

struct EmissionConnectKat {
  std::vector<uint8_t> wire;
  crypto::hash p_id{};
  std::vector<uint64_t> settlement_epochs;
  std::vector<uint64_t> reward_amount_plain;
};

std::vector<uint8_t> bytes_from_hex(const std::string& hex)
{
  std::string bin;
  if (!epee::string_tools::parse_hexstr_to_binbuff(hex, bin))
    throw std::runtime_error("invalid hex in emission-connect KAT");
  return {bin.begin(), bin.end()};
}

EmissionConnectKat load_emission_connect_kat()
{
  std::ifstream ifs(EMISSION_CONNECT_KAT_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing emission-connect KAT fixture at ") + EMISSION_CONNECT_KAT_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("emission_vin"))
    throw std::runtime_error("invalid emission-connect KAT fixture");

  const auto& vin = doc["emission_vin"];
  EmissionConnectKat kat{};
  kat.wire = bytes_from_hex(vin["wire_hex"].GetString());
  const std::vector<uint8_t> pid = bytes_from_hex(vin["p_canonical_id_hex"].GetString());
  if (pid.size() != sizeof(kat.p_id.data))
    throw std::runtime_error("emission-connect KAT p_canonical_id must be 32 bytes");
  std::memcpy(kat.p_id.data, pid.data(), pid.size());
  for (const auto& e : vin["settlement_epochs"].GetArray())
    kat.settlement_epochs.push_back(e.GetUint64());
  for (const auto& a : vin["reward_amount_plain"].GetArray())
    kat.reward_amount_plain.push_back(a.GetUint64());
  return kat;
}

constexpr uint64_t CONNECT_HEIGHT = 12345;

/// Records the connect arm's two observable effects: the single-writer claim
/// call and the vout storage shape handed to add_output.
class EmissionConnectDB: public BaseTestDB
{
public:
  using BlockchainDB::add_transaction;

  struct AppliedClaim {
    uint64_t block_height;
    crypto::hash p_id;
    std::vector<uint64_t> settlement_epochs;
  };
  struct StoredOutput {
    uint64_t amount;
    bool has_commitment;
    ct::key commitment;
  };

  EmissionConnectDB() { m_open = true; }

  // The connect arm reads height() — the count of stored blocks, which at
  // add_transaction time is the connecting block's index (F-B5a: the
  // block_heights row does not exist yet, so a hash lookup would throw).
  uint64_t height() const override { return CONNECT_HEIGHT; }

  void apply_archival_emission_claim(uint64_t block_height, const crypto::hash& p_id,
    const std::vector<uint64_t>& settlement_epochs) override
  {
    m_claims.push_back({block_height, p_id, settlement_epochs});
  }

  uint64_t add_output(const crypto::hash&, const cryptonote::tx_out& tx_output,
    const uint64_t&, const uint64_t, const ct::key* commitment) override
  {
    StoredOutput out{};
    out.amount = tx_output.amount;
    out.has_commitment = commitment != nullptr;
    if (commitment)
      out.commitment = *commitment;
    m_outputs.push_back(out);
    return m_outputs.size() - 1;
  }

  std::vector<AppliedClaim> m_claims;
  std::vector<StoredOutput> m_outputs;
};

/// Emission tx shape at connect: the fixture vin plus one reward vout
/// (plaintext amount, verCtSemanticsEmission already ran) and one amount-0
/// change vout, each with a distinct outPk commitment.
transaction make_emission_tx(const EmissionConnectKat& kat)
{
  transaction tx{};
  // Real emission txs are version 3 (min accepted version, blockchain.cpp);
  // the connect writer under test doesn't branch on it, but the fixture
  // matches the production surface so it cannot drift from it.
  tx.version = 3;

  txin_archival_reward_emission vin{};
  vin.canonical_bytes = kat.wire;
  tx.vin.push_back(vin);

  uint64_t total_reward = 0;
  for (uint64_t amount : kat.reward_amount_plain)
    total_reward += amount;

  const uint64_t amounts[2] = {total_reward, 0};
  for (size_t i = 0; i < 2; ++i)
  {
    tx_out vout{};
    vout.amount = amounts[i];
    txout_to_tagged_key tagged{};
    memset(&tagged.key, 0x30 + static_cast<int>(i), sizeof(tagged.key));
    tagged.view_tag.data = 0;
    vout.target = tagged;
    tx.vout.push_back(vout);

    ct::ctkey out_pk{};
    memset(out_pk.mask.bytes, 0x70 + static_cast<int>(i), sizeof(out_pk.mask.bytes));
    tx.ct_signatures.outPk.push_back(out_pk);
  }
  return tx;
}

void add_emission_tx(EmissionConnectDB& db, const transaction& tx)
{
  const crypto::hash tx_hash = crypto::null_hash;
  const crypto::hash tx_prunable_hash = crypto::null_hash;
  db.add_transaction(crypto::null_hash, std::make_pair(tx, blobdata_ref{}),
    /*block_height=*/0, &tx_hash, &tx_prunable_hash);
}

} // namespace

TEST(archival_emission_connect, extracts_operands_and_applies_claim)
{
  const EmissionConnectKat kat = load_emission_connect_kat();
  EmissionConnectDB db;
  add_emission_tx(db, make_emission_tx(kat));

  ASSERT_EQ(db.m_claims.size(), 1u);
  const auto& claim = db.m_claims[0];
  EXPECT_EQ(claim.block_height, CONNECT_HEIGHT);
  EXPECT_EQ(claim.p_id, kat.p_id);
  EXPECT_EQ(claim.settlement_epochs, kat.settlement_epochs);
}

TEST(archival_emission_connect, stores_vouts_amount_zero_with_commitments)
{
  const EmissionConnectKat kat = load_emission_connect_kat();
  const transaction tx = make_emission_tx(kat);
  EmissionConnectDB db;
  add_emission_tx(db, tx);

  // Both the plaintext reward vout and the amount-0 change vout store as
  // amount-0 RCT records with their outPk commitment preserved.
  ASSERT_EQ(db.m_outputs.size(), 2u);
  ASSERT_GT(tx.vout[0].amount, 0u);
  for (size_t i = 0; i < db.m_outputs.size(); ++i)
  {
    EXPECT_EQ(db.m_outputs[i].amount, 0u) << "vout " << i;
    ASSERT_TRUE(db.m_outputs[i].has_commitment) << "vout " << i;
    EXPECT_EQ(0, memcmp(db.m_outputs[i].commitment.bytes,
      tx.ct_signatures.outPk[i].mask.bytes, sizeof(ct::key))) << "vout " << i;
  }
}

TEST(archival_emission_connect, unparseable_vin_throws)
{
  const EmissionConnectKat kat = load_emission_connect_kat();
  transaction tx = make_emission_tx(kat);
  // Tag-correct garbage: passes the transport shim's shape check, fails the
  // Rust parse — the connect arm must hard-error, never soft-skip.
  auto& vin = std::get<txin_archival_reward_emission>(tx.vin[0]);
  vin.canonical_bytes.assign(16, 0x00);
  vin.canonical_bytes[0] = 0x04;

  EmissionConnectDB db;
  EXPECT_THROW(add_emission_tx(db, tx), std::runtime_error);
  EXPECT_TRUE(db.m_claims.empty());
}
