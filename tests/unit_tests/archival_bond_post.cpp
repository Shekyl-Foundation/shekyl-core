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
  // EU-D3 serving endpoint: JoinMarket-coupled like the key, written right
  // after it. Non-zero so present and absent (the zero key) are
  // distinguishable below.
  memset(bond.endpoint.data, 0x0E, sizeof(bond.endpoint.data));
  bond.holdings.kind = archival_holdings_kind::ShardSetCompact;
  bond.holdings.shard_ids = {7, 42};
  bond.bonded_total_atomic = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.bond_credit = bond.bonded_total_atomic;
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
      b.endpoint = crypto::public_key{}; // EU-D3: absent off JoinMarket
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

// EU-D3 at the binary serializer: the serving endpoint exists iff JoinMarket,
// as raw 32 bytes right after bond_spend_pk. The offset is derived by hand
// from the wire shape (not copied from Rust), so the two codecs agree on
// where the endpoint sits through the spec rather than through each other;
// a wire that ends before or inside the endpoint does not parse.
TEST(archival_bond_post, vin_serializer_enforces_endpoint_coupling)
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
  // tag ‖ varint(len) ‖ hybrid pk ‖ p_id ‖ kind ‖ varint(len) ‖ bond_spend_pk ‖ endpoint ‖ ...
  const size_t kind_off =
    1 + varint_size(config::PQC_HYBRID_SINGLE_KEY_LEN) + config::PQC_HYBRID_SINGLE_KEY_LEN
      + sizeof(crypto::hash);
  const size_t endpoint_off = kind_off + 1
    + varint_size(config::PQC_HYBRID_SINGLE_KEY_LEN) + config::PQC_HYBRID_SINGLE_KEY_LEN;

  std::string join_wire;
  ASSERT_TRUE(encode(make_join_market_vin(), join_wire));
  ASSERT_GT(join_wire.size(), endpoint_off + 32);
  {
    // JoinMarket round-trips its endpoint, and the bytes sit where the shape
    // says: 32 x 0x0E immediately after the 0xE5 debit authorizer.
    txin_v decoded;
    ASSERT_TRUE(decode(join_wire, decoded));
    EXPECT_TRUE(endpoint_is(std::get<txin_archival_bond_post>(decoded), 0x0E));
    ASSERT_EQ(static_cast<uint8_t>(join_wire[kind_off]),
      static_cast<uint8_t>(archival_bond_post_kind::JoinMarket));
    EXPECT_EQ(static_cast<uint8_t>(join_wire[endpoint_off - 1]), 0xE5u);
    EXPECT_EQ(join_wire.substr(endpoint_off, 32), std::string(32, static_cast<char>(0x0E)));
  }
  {
    // JoinMarket without an endpoint (the wire ends where the endpoint should
    // begin) and with a truncated one (31 of its 32 bytes) both fail to parse.
    txin_v decoded;
    EXPECT_FALSE(decode(join_wire.substr(0, endpoint_off), decoded));
    EXPECT_FALSE(decode(join_wire.substr(0, endpoint_off + 31), decoded));
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
    EXPECT_TRUE(std::get<txin_archival_bond_post>(decoded).join_market_coupled_fields_absent());
  }
  {
    // The kind bound is HoldingsUpdate: the byte one above it does not parse.
    std::string wire = join_wire;
    wire[kind_off] = static_cast<char>(
      static_cast<uint8_t>(archival_bond_post_kind::HoldingsUpdate) + 1);
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
  // EU-D3 mirrored: the endpoint round-trips on JoinMarket, a JoinMarket
  // archive that ends before (or inside) the endpoint throws on load, and a
  // stray endpoint on a Release throws on save.
  {
    EXPECT_TRUE(endpoint_is(boost_round_trip(make_join_market_vin()), 0x0E));
  }
  {
    std::stringstream ss;
    boost::archive::portable_binary_oarchive oar(ss);
    oar << make_join_market_vin();
    const std::string archive = ss.str();
    // The endpoint bytes (32 x 0x0E) occur exactly once in the archive: every
    // other field is a different fill.
    const std::string endpoint_bytes(32, static_cast<char>(0x0E));
    const size_t endpoint_off = archive.find(endpoint_bytes);
    ASSERT_NE(endpoint_off, std::string::npos);
    ASSERT_EQ(archive.find(endpoint_bytes, endpoint_off + 1), std::string::npos);
    // The archive encodes the key as char[32]: boost's per-class header and
    // the element count (0x20) precede the raw bytes. Everything between the
    // debit authorizer's last element (0xE5) and the 0x0E run is therefore
    // the endpoint's own encoding, so a prefix cut right after that 0xE5
    // leaves every earlier field complete and the endpoint read is the one
    // that runs out of stream.
    const size_t key_end = archive.rfind(static_cast<char>(0xE5), endpoint_off);
    ASSERT_NE(key_end, std::string::npos);
    const size_t endpoint_enc_off = key_end + 1;
    const std::string endpoint_prefix = archive.substr(endpoint_enc_off, endpoint_off - endpoint_enc_off);
    ASSERT_LE(endpoint_prefix.size(), 8u) << epee::to_hex::string(epee::strspan<std::uint8_t>(endpoint_prefix));
    ASSERT_NE(endpoint_prefix.find(static_cast<char>(0x20)), std::string::npos)
      << epee::to_hex::string(epee::strspan<std::uint8_t>(endpoint_prefix));
    const auto load_prefix_code = [&](size_t len) {
      std::stringstream in(archive.substr(0, len));
      boost::archive::portable_binary_iarchive iar(in);
      txin_archival_bond_post out{};
      try
      {
        iar >> out;
      }
      catch (const boost::archive::archive_exception& e)
      {
        return e.code;
      }
      return boost::archive::archive_exception::no_exception;
    };
    // Absent: the archive ends where the endpoint's encoding begins.
    EXPECT_EQ(load_prefix_code(endpoint_enc_off),
      boost::archive::archive_exception::input_stream_error);
    // Truncated: the count is there, 31 of the 32 bytes follow.
    EXPECT_EQ(load_prefix_code(endpoint_off + 31),
      boost::archive::archive_exception::input_stream_error);
  }
  {
    txin_archival_bond_post release_with_endpoint = make_join_market_vin();
    release_with_endpoint.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    release_with_endpoint.bond_spend_pk.clear();
    EXPECT_THROW(boost_round_trip(release_with_endpoint), boost::archive::archive_exception);
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
  // EU-D3 at the JSON codec, write and read.
  {
    // JoinMarket emits and reads back its endpoint.
    const std::string json = to_json(make_join_market_vin());
    rapidjson::Document doc;
    ASSERT_FALSE(doc.Parse(json.c_str()).HasParseError());
    ASSERT_TRUE(doc.HasMember("endpoint"));
    txin_archival_bond_post out{};
    cryptonote::json::fromJsonValue(doc, out);
    EXPECT_TRUE(endpoint_is(out, 0x0E));
    // A JoinMarket object without the endpoint member is refused on read ...
    doc.RemoveMember("endpoint");
    EXPECT_THROW(cryptonote::json::fromJsonValue(doc, out), cryptonote::json::MISSING_KEY);
    // ... and so is one whose endpoint is truncated (31 of 32 bytes).
    doc.AddMember("endpoint",
      rapidjson::Value("0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"),
      doc.GetAllocator());
    EXPECT_THROW(cryptonote::json::fromJsonValue(doc, out), cryptonote::json::BAD_INPUT);
  }
  {
    // A Release carrying an endpoint is refused on write.
    txin_archival_bond_post release_with_endpoint = make_join_market_vin();
    release_with_endpoint.post_kind = static_cast<uint8_t>(archival_bond_post_kind::Release);
    release_with_endpoint.bond_spend_pk.clear();
    EXPECT_THROW(to_json(release_with_endpoint), cryptonote::json::WRONG_TYPE);
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
