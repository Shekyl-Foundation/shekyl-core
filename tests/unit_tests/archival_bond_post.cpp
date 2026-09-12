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
#include "fcmp/ct_ops.h"
#include "fcmp/ct_semantics.h"
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
  // EU-D3 serving endpoint: JoinMarket-coupled (with EndpointUpdate). Non-zero
  // so present and absent (the zero key) are distinguishable below.
  memset(bond.endpoint.data, 0x0E, sizeof(bond.endpoint.data));
  bond.holdings.kind = archival_holdings_kind::ShardSetCompact;
  bond.holdings.shard_ids = {7, 42};
  bond.bonded_total_atomic = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.bond_credit = bond.bonded_total_atomic;
  bond.bond_debit = 0;
  return bond;
}

/// The EU-D11 shape: exactly the endpoint. Built from the JoinMarket fixture
/// so the identity fields match and only the kind-coupled ones differ.
txin_archival_bond_post make_endpoint_update_vin()
{
  txin_archival_bond_post bond = make_join_market_vin();
  bond.post_kind = static_cast<uint8_t>(archival_bond_post_kind::EndpointUpdate);
  bond.bond_spend_pk.clear();
  memset(bond.endpoint.data, 0x4E, sizeof(bond.endpoint.data));
  bond.holdings = archival_holdings_descriptor{};
  bond.bonded_total_atomic = 0;
  bond.bond_credit = 0;
  bond.bond_debit = 0;
  return bond;
}

bool endpoint_is(const txin_archival_bond_post& v, uint8_t fill)
{
  crypto::public_key expect{};
  memset(expect.data, fill, sizeof(expect.data));
  return memcmp(v.endpoint.data, expect.data, sizeof(expect.data)) == 0;
}

size_t varint_size(uint64_t v)
{
  size_t n = 1;
  while (v >= 0x80) { v >>= 7; ++n; }
  return n;
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
    txin_v vin_release_with_key = [] {
      txin_archival_bond_post b = make_join_market_vin();
      b.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
      b.holdings.shard_ids.clear();
      b.bonded_total_atomic = 0;
      b.bond_credit = 0;
      b.bond_debit = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
      return b; // bond_spend_pk still set: forbidden off JoinMarket
    }();
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    EXPECT_FALSE(::do_serialize(oar, vin_release_with_key));
  }
  {
    // The same Release vin without the key serializes and round-trips key-less.
    txin_v vin_release = [] {
      txin_archival_bond_post b = make_join_market_vin();
      b.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
      b.bond_spend_pk.clear();
      b.endpoint = crypto::public_key{}; // EU-D3: absent off JoinMarket/EndpointUpdate
      b.holdings.shard_ids.clear();
      b.bonded_total_atomic = 0;
      b.bond_credit = 0;
      b.bond_debit = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
      return b;
    }();
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    ASSERT_TRUE(::do_serialize(oar, vin_release));
    const std::string wire = oss.str();
    txin_v decoded;
    binary_archive<false> iar({reinterpret_cast<const uint8_t*>(wire.data()), wire.size()});
    ASSERT_TRUE(::do_serialize(iar, decoded));
    const auto& out = std::get<txin_archival_bond_post>(decoded);
    EXPECT_TRUE(out.bond_spend_pk.empty());
    EXPECT_EQ(out.bond_debit, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);
  }
}

// EU-D3 / EU-D11 at the binary serializer: the endpoint exists iff JoinMarket
// or EndpointUpdate, and the kind-4 vin is exactly the endpoint. The
// round-trip pins the byte length, so a field silently added to (or dropped
// from) the kind-4 wire shape shows up as a count, not as a passing decode.
TEST(archival_bond_post, vin_serializer_enforces_endpoint_coupling_and_kind4_shape)
{
  const auto encode = [](const txin_v& vin, std::string& wire) {
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    const bool ok = ::do_serialize(oar, const_cast<txin_v&>(vin));
    wire = oss.str();
    return ok;
  };
  const auto decode = [](const std::string& wire, txin_v& out) {
    binary_archive<false> iar({reinterpret_cast<const uint8_t*>(wire.data()), wire.size()});
    return ::do_serialize(iar, out);
  };

  {
    // JoinMarket round-trips its endpoint.
    std::string wire;
    ASSERT_TRUE(encode(make_join_market_vin(), wire));
    txin_v decoded;
    ASSERT_TRUE(decode(wire, decoded));
    EXPECT_TRUE(endpoint_is(std::get<txin_archival_bond_post>(decoded), 0x0E));
  }
  {
    // EndpointUpdate is exactly the endpoint: tag ‖ len ‖ pk ‖ p_id ‖ kind ‖ endpoint.
    std::string wire;
    ASSERT_TRUE(encode(make_endpoint_update_vin(), wire));
    EXPECT_EQ(wire.size(),
      1 + varint_size(config::PQC_HYBRID_SINGLE_KEY_LEN) + config::PQC_HYBRID_SINGLE_KEY_LEN
        + sizeof(crypto::hash) + 1 + 32);
    txin_v decoded;
    ASSERT_TRUE(decode(wire, decoded));
    const auto& out = std::get<txin_archival_bond_post>(decoded);
    EXPECT_EQ(out.post_kind, static_cast<uint8_t>(archival_bond_post_kind::EndpointUpdate));
    EXPECT_TRUE(endpoint_is(out, 0x4E));
    EXPECT_TRUE(out.bond_spend_pk.empty());
    EXPECT_TRUE(out.is_endpoint_update_shape());
  }
  {
    // A Release carrying an endpoint is a misconstruction: refused on write.
    txin_archival_bond_post release = make_join_market_vin();
    release.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    release.bond_spend_pk.clear();
    release.holdings.shard_ids.clear();
    release.bonded_total_atomic = 0;
    release.bond_credit = 0;
    release.bond_debit = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
    std::string wire;
    EXPECT_FALSE(encode(release, wire));
    // ... and the same Release without one serializes and reads back absent.
    release.endpoint = crypto::public_key{};
    ASSERT_TRUE(encode(release, wire));
    txin_v decoded;
    ASSERT_TRUE(decode(wire, decoded));
    EXPECT_FALSE(std::get<txin_archival_bond_post>(decoded).has_endpoint());
  }
  {
    // EU-D11: a kind-4 vin carrying holdings or an amount term is refused on
    // write — the wire has no slot for them, so they cannot be "dropped".
    txin_archival_bond_post with_holdings = make_endpoint_update_vin();
    with_holdings.holdings.shard_ids = {7};
    std::string wire;
    EXPECT_FALSE(encode(with_holdings, wire));
    txin_archival_bond_post with_term = make_endpoint_update_vin();
    with_term.bond_credit = 1;
    EXPECT_FALSE(encode(with_term, wire));
  }
  {
    // The kind bound moved with the enum: 5 does not parse.
    std::string wire;
    ASSERT_TRUE(encode(make_endpoint_update_vin(), wire));
    const size_t kind_off =
      1 + varint_size(config::PQC_HYBRID_SINGLE_KEY_LEN) + config::PQC_HYBRID_SINGLE_KEY_LEN
        + sizeof(crypto::hash);
    ASSERT_EQ(static_cast<uint8_t>(wire[kind_off]),
      static_cast<uint8_t>(archival_bond_post_kind::EndpointUpdate));
    wire[kind_off] = static_cast<char>(5);
    txin_v decoded;
    EXPECT_FALSE(decode(wire, decoded));
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
    txin_archival_bond_post release_with_key = make_join_market_vin();
    release_with_key.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    EXPECT_THROW(boost_round_trip(release_with_key), boost::archive::archive_exception);
  }
  {
    txin_archival_bond_post release = make_join_market_vin();
    release.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    release.bond_spend_pk.clear();
    release.endpoint = crypto::public_key{};
    EXPECT_TRUE(boost_round_trip(release).bond_spend_pk.empty());
  }
  // EU-D3 / EU-D11 mirrored: the endpoint round-trips on its two kinds, a
  // stray endpoint on a Release throws, and a kind-4 vin carrying holdings or
  // a term throws instead of being silently truncated.
  {
    EXPECT_TRUE(endpoint_is(boost_round_trip(make_join_market_vin()), 0x0E));
    const txin_archival_bond_post out = boost_round_trip(make_endpoint_update_vin());
    EXPECT_TRUE(endpoint_is(out, 0x4E));
    EXPECT_TRUE(out.is_endpoint_update_shape());
  }
  {
    txin_archival_bond_post release_with_endpoint = make_join_market_vin();
    release_with_endpoint.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    release_with_endpoint.bond_spend_pk.clear();
    EXPECT_THROW(boost_round_trip(release_with_endpoint), boost::archive::archive_exception);
  }
  {
    txin_archival_bond_post with_term = make_endpoint_update_vin();
    with_term.bond_debit = 1;
    EXPECT_THROW(boost_round_trip(with_term), boost::archive::archive_exception);
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
    txin_archival_bond_post release_with_key = make_join_market_vin();
    release_with_key.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    EXPECT_THROW(to_json(release_with_key), cryptonote::json::WRONG_TYPE);
  }
  // EU-D3 / EU-D11 at the JSON codec, write and read.
  {
    const std::string json = to_json(make_endpoint_update_vin());
    rapidjson::Document doc;
    ASSERT_FALSE(doc.Parse(json.c_str()).HasParseError());
    EXPECT_TRUE(doc.HasMember("endpoint"));
    EXPECT_FALSE(doc.HasMember("holdings"));
    EXPECT_FALSE(doc.HasMember("bond_credit"));
    txin_archival_bond_post out{};
    cryptonote::json::fromJsonValue(doc, out);
    EXPECT_TRUE(endpoint_is(out, 0x4E));
    EXPECT_TRUE(out.is_endpoint_update_shape());
  }
  {
    txin_archival_bond_post release_with_endpoint = make_join_market_vin();
    release_with_endpoint.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    release_with_endpoint.bond_spend_pk.clear();
    EXPECT_THROW(to_json(release_with_endpoint), cryptonote::json::WRONG_TYPE);
    txin_archival_bond_post kind4_with_term = make_endpoint_update_vin();
    kind4_with_term.bonded_total_atomic = 1;
    EXPECT_THROW(to_json(kind4_with_term), cryptonote::json::WRONG_TYPE);
  }
  {
    // Read side refuses, not ignores: a JoinMarket object re-labelled kind 4
    // still carries holdings and terms, and must not parse as a rotation.
    const std::string json = to_json(make_join_market_vin());
    rapidjson::Document doc;
    ASSERT_FALSE(doc.Parse(json.c_str()).HasParseError());
    doc["post_kind"].SetUint(static_cast<unsigned>(archival_bond_post_kind::EndpointUpdate));
    doc.RemoveMember("bond_spend_pk");
    txin_archival_bond_post out{};
    EXPECT_THROW(cryptonote::json::fromJsonValue(doc, out), cryptonote::json::WRONG_TYPE);
  }
  {
    // ... and a Release object with an endpoint member is refused on read.
    txin_archival_bond_post release = make_join_market_vin();
    release.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    release.bond_spend_pk.clear();
    release.endpoint = crypto::public_key{};
    const std::string json = to_json(release);
    rapidjson::Document doc;
    ASSERT_FALSE(doc.Parse(json.c_str()).HasParseError());
    doc.AddMember("endpoint",
      rapidjson::Value("4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e"),
      doc.GetAllocator());
    txin_archival_bond_post out{};
    EXPECT_THROW(cryptonote::json::fromJsonValue(doc, out), cryptonote::json::WRONG_TYPE);
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

  ct::CtSig rv{};
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(ct::scalarmultH(ct::d2h(amount)));

  EXPECT_FALSE(ct::verCtSemanticsBondPost(rv, 0, 0));
}

TEST(archival_bond_post, rct_balance_includes_bond_credit_term)
{
  constexpr uint64_t bond_credit = 750'000'000;

  ct::CtSig rv{};
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(ct::scalarmultH(ct::d2h(bond_credit)));

  EXPECT_FALSE(ct::verCtSemanticsSimple(rv));
  EXPECT_TRUE(ct::verCtSemanticsBondPost(rv, bond_credit, 0));
  EXPECT_FALSE(ct::verCtSemanticsBondPost(rv, bond_credit - 1, 0));
  EXPECT_FALSE(ct::verCtSemanticsBondPost(rv, 0, bond_credit));
}

TEST(archival_bond_post, rct_balance_rejects_noncanonical_bulletproof_layout)
{
  constexpr uint64_t bond_debit = 500'000'000;

  ct::CtSig rv{};
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  const ct::key mask_scalar = ct::skGen();
  rv.outPk.resize(2);
  rv.outPk[0].mask = ct::commit(bond_debit / 2, mask_scalar);
  rv.outPk[1].mask = ct::commit(bond_debit / 2, mask_scalar);
  rv.enc_amounts.resize(2);
  rv.enc_labels.resize(2);
  // Two outputs share one blinding scalar → pseudo must carry 2× that blinding so the
  // bond balance equation holds; failure is then only the non-canonical two-proof layout.
  const ct::key zero_mask = ct::commit(0, mask_scalar);
  rv.p.pseudoOuts.push_back(ct::addKeys(zero_mask, zero_mask));
  rv.p.bulletproofs_plus.push_back(ct::bulletproof_plus_PROVE(bond_debit / 2, mask_scalar));
  rv.p.bulletproofs_plus.push_back(ct::bulletproof_plus_PROVE(bond_debit / 2, mask_scalar));

  EXPECT_FALSE(ct::verCtSemanticsBondPost(rv, 0, bond_debit));
}

TEST(archival_bond_post, rct_balance_includes_bond_debit_term)
{
  constexpr uint64_t bond_debit = 500'000'000;

  ct::CtSig rv{};
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  const ct::key mask_scalar = ct::skGen();
  rv.outPk.resize(1);
  rv.outPk[0].mask = ct::commit(bond_debit, mask_scalar);
  rv.enc_amounts.resize(1);
  rv.enc_labels.resize(1);
  // Funding input contributes only blinding; bond_debit is the cleartext source term.
  rv.p.pseudoOuts.push_back(ct::commit(0, mask_scalar));
  rv.p.bulletproofs_plus.push_back(ct::bulletproof_plus_PROVE(bond_debit, mask_scalar));

  EXPECT_FALSE(ct::verCtSemanticsSimple(rv));
  EXPECT_TRUE(ct::verCtSemanticsBondPost(rv, 0, bond_debit));
  EXPECT_FALSE(ct::verCtSemanticsBondPost(rv, bond_debit, 0));
}

// EU-D11 at the CT-semantics dispatch: an EndpointUpdate balances with NO bond
// term through its own entry, while the bond-post entry keeps refusing the
// zero-term shape — the two are different checks, not one with (0, 0).
TEST(archival_bond_post, rct_balance_endpoint_update_has_no_bond_term)
{
  ct::CtSig rv{};
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  const ct::key mask_scalar = ct::skGen();
  rv.outPk.resize(1);
  rv.outPk[0].mask = ct::commit(0, mask_scalar);
  rv.enc_amounts.resize(1);
  rv.enc_labels.resize(1);
  // The funding input contributes only blinding; nothing is credited or debited.
  rv.p.pseudoOuts.push_back(ct::commit(0, mask_scalar));
  rv.p.bulletproofs_plus.push_back(ct::bulletproof_plus_PROVE(0, mask_scalar));

  EXPECT_TRUE(ct::verCtSemanticsEndpointUpdate(rv));
  EXPECT_FALSE(ct::verCtSemanticsBondPost(rv, 0, 0));
  // A fee with nothing funding it is a sum mismatch on the kind-4 path too.
  rv.txnFee = 1;
  EXPECT_FALSE(ct::verCtSemanticsEndpointUpdate(rv));
}
