// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"

#include <cstring>
#include <sstream>
#include <variant>

#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>
#include <rapidjson/document.h>

#include "byte_stream.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "fcmp/bulletproofs_plus.h"
#include "fcmp/rctOps.h"
#include "fcmp/rctSigs.h"
#include "serialization/binary_archive.h"
#include "serialization/json_object.h"
#include "shekyl/consensus_constants_generated.h"

using namespace cryptonote;

namespace {

txin_archival_bond_post make_join_market_vin()
{
  txin_archival_bond_post bond{};
  // Exact canonical single-key length: the serializer rejects any other size.
  bond.hybrid_public_key.assign(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xAB);
  memset(&bond.p_canonical_id, 0x11, sizeof(bond.p_canonical_id));
  bond.post_kind = static_cast<uint8_t>(archival_bond_post_kind::JoinMarket);
  // GF-1 debit authorizer: JoinMarket-coupled on the wire (§9.11), exact
  // canonical length enforced by the serializer.
  bond.bond_spend_pk.assign(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xE5);
  bond.holdings.kind = archival_holdings_kind::ShardSetCompact;
  bond.holdings.shard_ids = {7, 42};
  bond.bonded_total_atomic = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.bond_credit = bond.bonded_total_atomic;
  bond.bond_debit = 0;
  return bond;
}

} // namespace

TEST(archival_bond_post, vin_deserializes_with_tag_0x03)
{
  txin_v vin = make_join_market_vin();

  std::ostringstream oss;
  binary_archive<true> oar(oss);
  ASSERT_TRUE(::do_serialize(oar, vin));
  const std::string wire = oss.str();
  ASSERT_FALSE(wire.empty());
  EXPECT_EQ(static_cast<uint8_t>(wire[0]), 0x03u);

  txin_v decoded;
  binary_archive<false> iar({reinterpret_cast<const uint8_t*>(wire.data()), wire.size()});
  ASSERT_TRUE(::do_serialize(iar, decoded));
  ASSERT_TRUE(std::holds_alternative<txin_archival_bond_post>(decoded));

  const auto& out = std::get<txin_archival_bond_post>(decoded);
  EXPECT_EQ(out.holdings.shard_ids.size(), 2u);
  EXPECT_EQ(out.holdings.shard_ids[0], 7u);
  EXPECT_EQ(out.holdings.shard_ids[1], 42u);
  EXPECT_EQ(out.bond_credit, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);
  EXPECT_EQ(out.post_kind, static_cast<uint8_t>(archival_bond_post_kind::JoinMarket));
  // GF-1: the committed debit authorizer round-trips byte-exactly.
  EXPECT_EQ(out.bond_spend_pk,
    std::vector<uint8_t>(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xE5));
}

// §9.11 coupling at the C++ serializer: JoinMarket without a canonical-length
// bond_spend_pk refuses to serialize, and a non-JoinMarket vin carrying one
// refuses too (it would otherwise be silently dropped from the bytes).
TEST(archival_bond_post, vin_serializer_enforces_bond_spend_pk_coupling)
{
  {
    txin_v vin_missing_key = [] {
      txin_archival_bond_post b = make_join_market_vin();
      b.bond_spend_pk.clear();
      return b;
    }();
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    EXPECT_FALSE(::do_serialize(oar, vin_missing_key));
  }
  {
    txin_v vin_truncated_key = [] {
      txin_archival_bond_post b = make_join_market_vin();
      b.bond_spend_pk.assign(config::PQC_HYBRID_SINGLE_KEY_LEN - 1, 0xE5);
      return b;
    }();
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    EXPECT_FALSE(::do_serialize(oar, vin_truncated_key));
  }
  {
    txin_v vin_unbond_with_key = [] {
      txin_archival_bond_post b = make_join_market_vin();
      b.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Unbond);
      b.holdings.shard_ids.clear();
      b.bonded_total_atomic = 0;
      b.bond_credit = 0;
      b.bond_debit = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
      return b; // bond_spend_pk still set: forbidden off JoinMarket
    }();
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    EXPECT_FALSE(::do_serialize(oar, vin_unbond_with_key));
  }
  {
    // The same Unbond vin without the key serializes and round-trips key-less.
    txin_v vin_unbond = [] {
      txin_archival_bond_post b = make_join_market_vin();
      b.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Unbond);
      b.bond_spend_pk.clear();
      b.holdings.shard_ids.clear();
      b.bonded_total_atomic = 0;
      b.bond_credit = 0;
      b.bond_debit = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
      return b;
    }();
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    ASSERT_TRUE(::do_serialize(oar, vin_unbond));
    const std::string wire = oss.str();
    txin_v decoded;
    binary_archive<false> iar({reinterpret_cast<const uint8_t*>(wire.data()), wire.size()});
    ASSERT_TRUE(::do_serialize(iar, decoded));
    const auto& out = std::get<txin_archival_bond_post>(decoded);
    EXPECT_TRUE(out.bond_spend_pk.empty());
    EXPECT_EQ(out.bond_debit, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);
  }
}

// §9.11 coupling at the boost serializer (blob/pool paths): the same shapes
// the binary codec refuses must refuse here too — on save so a
// misconstruction is loud instead of silently dropping the key, and (same
// direction-agnostic branch) on load so a non-canonical key can never enter
// memory through a boost archive when every other codec pins the length.
TEST(archival_bond_post, boost_serializer_enforces_bond_spend_pk_coupling)
{
  const auto boost_round_trip = [](const txin_archival_bond_post& in) {
    std::stringstream ss;
    boost::archive::portable_binary_oarchive oar(ss);
    oar << in;
    txin_archival_bond_post out{};
    boost::archive::portable_binary_iarchive iar(ss);
    iar >> out;
    return out;
  };

  {
    const txin_archival_bond_post out = boost_round_trip(make_join_market_vin());
    EXPECT_EQ(out.bond_spend_pk,
      std::vector<uint8_t>(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xE5));
  }
  {
    txin_archival_bond_post missing_key = make_join_market_vin();
    missing_key.bond_spend_pk.clear();
    EXPECT_THROW(boost_round_trip(missing_key), boost::archive::archive_exception);
  }
  {
    txin_archival_bond_post truncated_key = make_join_market_vin();
    truncated_key.bond_spend_pk.assign(config::PQC_HYBRID_SINGLE_KEY_LEN - 1, 0xE5);
    EXPECT_THROW(boost_round_trip(truncated_key), boost::archive::archive_exception);
  }
  {
    txin_archival_bond_post unbond_with_key = make_join_market_vin();
    unbond_with_key.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Unbond);
    EXPECT_THROW(boost_round_trip(unbond_with_key), boost::archive::archive_exception);
  }
  {
    txin_archival_bond_post unbond = make_join_market_vin();
    unbond.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Unbond);
    unbond.bond_spend_pk.clear();
    EXPECT_TRUE(boost_round_trip(unbond).bond_spend_pk.empty());
  }
}

// §9.11 coupling at the JSON codec: toJsonValue refuses at write exactly what
// fromJsonValue refuses at read, so the daemon can never emit JSON its own
// parser rejects (the failure belongs to the producer, not the consumer).
TEST(archival_bond_post, json_codec_enforces_bond_spend_pk_coupling)
{
  const auto to_json = [](const txin_archival_bond_post& in) {
    epee::byte_stream buffer;
    rapidjson::Writer<epee::byte_stream> dest{buffer};
    cryptonote::json::toJsonValue(dest, in);
    return std::string(reinterpret_cast<const char*>(buffer.data()), buffer.size());
  };

  {
    // Valid JoinMarket round-trips through write + parse.
    const std::string json = to_json(make_join_market_vin());
    rapidjson::Document doc;
    ASSERT_FALSE(doc.Parse(json.c_str()).HasParseError());
    txin_archival_bond_post out{};
    cryptonote::json::fromJsonValue(doc, out);
    EXPECT_EQ(out.bond_spend_pk,
      std::vector<uint8_t>(config::PQC_HYBRID_SINGLE_KEY_LEN, 0xE5));
  }
  {
    txin_archival_bond_post missing_key = make_join_market_vin();
    missing_key.bond_spend_pk.clear();
    EXPECT_THROW(to_json(missing_key), cryptonote::json::WRONG_TYPE);
  }
  {
    txin_archival_bond_post truncated_key = make_join_market_vin();
    truncated_key.bond_spend_pk.assign(config::PQC_HYBRID_SINGLE_KEY_LEN - 1, 0xE5);
    EXPECT_THROW(to_json(truncated_key), cryptonote::json::WRONG_TYPE);
  }
  {
    txin_archival_bond_post unbond_with_key = make_join_market_vin();
    unbond_with_key.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Unbond);
    EXPECT_THROW(to_json(unbond_with_key), cryptonote::json::WRONG_TYPE);
  }
}

TEST(archival_bond_post, bond_floor_matches_shard_count)
{
  archival_holdings_descriptor holdings{};
  holdings.kind = archival_holdings_kind::ShardSetCompact;
  holdings.shard_ids = {1, 2, 3};
  EXPECT_EQ(archival_bond_floor(holdings), 3 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);

  holdings.kind = archival_holdings_kind::CompleteTree;
  holdings.shard_ids.clear();
  EXPECT_EQ(archival_bond_floor(holdings), SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);
}

TEST(archival_bond_post, tx_input_mixing_rejects_bond_with_serve_credit)
{
  transaction tx{};
  tx.vin.push_back(make_join_market_vin());
  tx.vin.push_back(txin_archival_serve_credit_response{});
  EXPECT_FALSE(check_inputs_types_supported(tx));
}

TEST(archival_bond_post, rct_balance_rejects_zero_bond_terms)
{
  constexpr uint64_t amount = 750'000'000;

  rct::rctSig rv{};
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(rct::scalarmultH(rct::d2h(amount)));

  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, 0, 0));
}

TEST(archival_bond_post, rct_balance_includes_bond_credit_term)
{
  constexpr uint64_t bond_credit = 750'000'000;

  rct::rctSig rv{};
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(rct::scalarmultH(rct::d2h(bond_credit)));

  EXPECT_FALSE(rct::verRctSemanticsSimple(rv));
  EXPECT_TRUE(rct::verRctSemanticsBondPost(rv, bond_credit, 0));
  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, bond_credit - 1, 0));
  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, 0, bond_credit));
}

TEST(archival_bond_post, rct_balance_rejects_noncanonical_bulletproof_layout)
{
  constexpr uint64_t bond_debit = 500'000'000;

  rct::rctSig rv{};
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  const rct::key mask_scalar = rct::skGen();
  rv.outPk.resize(2);
  rv.outPk[0].mask = rct::commit(bond_debit / 2, mask_scalar);
  rv.outPk[1].mask = rct::commit(bond_debit / 2, mask_scalar);
  rv.enc_amounts.resize(2);
  rv.enc_labels.resize(2);
  // Two outputs share one blinding scalar → pseudo must carry 2× that blinding so the
  // bond balance equation holds; failure is then only the non-canonical two-proof layout.
  const rct::key zero_mask = rct::commit(0, mask_scalar);
  rv.p.pseudoOuts.push_back(rct::addKeys(zero_mask, zero_mask));
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(bond_debit / 2, mask_scalar));
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(bond_debit / 2, mask_scalar));

  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, 0, bond_debit));
}

TEST(archival_bond_post, rct_balance_includes_bond_debit_term)
{
  constexpr uint64_t bond_debit = 500'000'000;

  rct::rctSig rv{};
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  const rct::key mask_scalar = rct::skGen();
  rv.outPk.resize(1);
  rv.outPk[0].mask = rct::commit(bond_debit, mask_scalar);
  rv.enc_amounts.resize(1);
  rv.enc_labels.resize(1);
  // Funding input contributes only blinding; bond_debit is the cleartext source term.
  rv.p.pseudoOuts.push_back(rct::commit(0, mask_scalar));
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(bond_debit, mask_scalar));

  EXPECT_FALSE(rct::verRctSemanticsSimple(rv));
  EXPECT_TRUE(rct::verRctSemanticsBondPost(rv, 0, bond_debit));
  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, bond_debit, 0));
}
