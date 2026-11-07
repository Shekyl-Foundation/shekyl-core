// Copyright (c) 2025-2026, The Shekyl Foundation
// Copyright (c) 2014-2022, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <sstream>
#include <vector>

#include "fcmp/ct_types.h"
#include "fcmp/ct_semantics.h"
#include "fcmp/ct_ops.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace std;
using namespace crypto;
using namespace ct;

namespace {

crypto::hash hash_ctsig_base_component(const ct::CtSig &rv)
{
  std::stringstream ss;
  binary_archive<true> ba(ss);
  const size_t inputs = rv.p.pseudoOuts.size();
  const size_t outputs = rv.enc_amounts.size();
  ct::CtSig mutable_rv = rv;
  CHECK_AND_ASSERT_THROW_MES(
      mutable_rv.serialize_ctsig_base(ba, inputs, outputs),
      "serialize_ctsig_base failed in test");
  return cryptonote::get_blob_hash(ss.str());
}

} // namespace

TEST(fcmp, HPow2)
{
  key G = scalarmultBase(d2h(1));

  // Note that H is computed differently than standard hashing
  // This method is not guaranteed to return a curvepoint for all inputs
  // Don't use it elsewhere
  key H = cn_fast_hash(G);
  ge_p3 H_p3;
  int decode = ge_frombytes_vartime(&H_p3, H.bytes);
  ASSERT_EQ(decode, 0); // this is known to pass for the particular value G
  ge_p2 H_p2;
  ge_p3_to_p2(&H_p2, &H_p3);
  ge_p1p1 H8_p1p1;
  ge_mul8(&H8_p1p1, &H_p2);
  ge_p1p1_to_p3(&H_p3, &H8_p1p1);
  ge_p3_tobytes(H.bytes, &H_p3);

  for (int j = 0 ; j < ATOMS ; j++) {
    ASSERT_TRUE(equalKeys(H, H2[j]));
    addKeys(H, H, H);
  }
}

static const xmr_amount test_amounts[]={0, 1, 2, 3, 4, 5, 10000, 10000000000000000000ull, 10203040506070809000ull, 123456789123456789};

TEST(fcmp, d2h)
{
  key k, P1;
  skpkGen(k, P1);
  for (auto amount: test_amounts) {
    d2h(k, amount);
    ASSERT_TRUE(amount == h2d(k));
  }
}

TEST(fcmp, d2b)
{
  for (auto amount: test_amounts) {
    bits b;
    d2b(b, amount);
    ASSERT_TRUE(amount == b2d(b));
  }
}

TEST(fcmp, key_ostream)
{
  std::stringstream out;
  out << "BEGIN" << ct::H << "END";
  EXPECT_EQ(
    std::string{"BEGIN<8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94>END"},
    out.str()
  );
}

TEST(fcmp, zeroCommmit)
{
  static const uint64_t amount = crypto::rand<uint64_t>();
  const ct::key z = ct::zeroCommit(amount);
  const ct::key a = ct::scalarmultBase(ct::identity());
  const ct::key b = ct::scalarmultH(ct::d2h(amount));
  const ct::key manual = ct::addKeys(a, b);
  ASSERT_EQ(z, manual);
}

static ct::key uncachedZeroCommit(uint64_t amount)
{
  const ct::key am = ct::d2h(amount);
  const ct::key bH = ct::scalarmultH(am);
  return ct::addKeys(ct::G, bH);
}

TEST(fcmp, zeroCommitCache)
{
  ASSERT_EQ(ct::zeroCommit(0), uncachedZeroCommit(0));
  ASSERT_EQ(ct::zeroCommit(1), uncachedZeroCommit(1));
  ASSERT_EQ(ct::zeroCommit(2), uncachedZeroCommit(2));
  ASSERT_EQ(ct::zeroCommit(10), uncachedZeroCommit(10));
  ASSERT_EQ(ct::zeroCommit(200), uncachedZeroCommit(200));
  ASSERT_EQ(ct::zeroCommit(1000000000), uncachedZeroCommit(1000000000));
  ASSERT_EQ(ct::zeroCommit(3000000000000), uncachedZeroCommit(3000000000000));
  ASSERT_EQ(ct::zeroCommit(900000000000000), uncachedZeroCommit(900000000000000));
}

TEST(fcmp, H)
{
  ge_p3 p3;
  ASSERT_EQ(ge_frombytes_vartime(&p3, ct::H.bytes), 0);
  ASSERT_EQ(memcmp(&p3, &ge_p3_H, sizeof(ge_p3)), 0);
}

TEST(fcmp, mul8)
{
  ge_p3 p3;
  ct::key key;
  ASSERT_EQ(ct::scalarmult8(ct::identity()), ct::identity());
  ct::scalarmult8(p3,ct::identity());
  ge_p3_tobytes(key.bytes, &p3);
  ASSERT_EQ(key, ct::identity());
  ASSERT_EQ(ct::scalarmult8(ct::H), ct::scalarmultKey(ct::H, ct::EIGHT));
  ct::scalarmult8(p3,ct::H);
  ge_p3_tobytes(key.bytes, &p3);
  ASSERT_EQ(key, ct::scalarmultKey(ct::H, ct::EIGHT));
  ASSERT_EQ(ct::scalarmultKey(ct::scalarmultKey(ct::H, ct::INV_EIGHT), ct::EIGHT), ct::H);
}

// ──────────────────────────────────────────────────────────────────────
// FCMP++ / PQC-specific tests (Phase 7)
// ──────────────────────────────────────────────────────────────────────

TEST(fcmp, CTTypeFcmpPlusPlusPqc_serialization_roundtrip)
{
  // Round-trips the rct base through `serialize_ctsig_base` — the ONLY
  // encoding of the base (the transaction serializer, the tx-hash paths, the
  // FCMP++ pre-hash, and the PQC payload binding all call it). A standalone
  // object serializer used to exist and was round-tripped here instead; it
  // was caller-less in production, laxer than the real wire (it accepted
  // states the member serializer rejects), and was deleted in the
  // dead-serializer cleanup (CT_SURFACE_NAMING_PIN.md §2). The prunable
  // section's real-path round-trip is covered at the transaction level
  // (tests/unit_tests/serialization.cpp and the shekyl-wire KATs).
  ct::CtSig rv;
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  memset(&rv.referenceBlock, 0xAB, sizeof(rv.referenceBlock));

  std::array<uint8_t, 9> enc_amt;
  enc_amt.fill(0x42);
  rv.enc_amounts.push_back(enc_amt);

  std::array<uint8_t, 9> enc_lbl;
  for (size_t i = 0; i < 8; ++i)
    enc_lbl[i] = static_cast<uint8_t>(0x50 + i);
  enc_lbl[8] = 0xE1;
  rv.enc_labels.push_back(enc_lbl);

  ct::ctkey outpk;
  outpk.dest = ct::pkGen();
  outpk.mask = ct::pkGen();
  rv.outPk.push_back(outpk);

  const size_t inputs = 1;
  const size_t outputs = 1;

  // Serialize (real wire path)
  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(rv.serialize_ctsig_base(ar, inputs, outputs));
    blob = oss.str();
  }

  // Deserialize
  ct::CtSig rv2;
  {
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(blob.data()), blob.size()});
    ASSERT_TRUE(rv2.serialize_ctsig_base(ar, inputs, outputs));
  }

  ASSERT_EQ(rv2.type, ct::CTTypeFcmpPlusPlusPqc);
  ASSERT_EQ(rv2.txnFee, rv.txnFee);
  ASSERT_EQ(rv2.referenceBlock, rv.referenceBlock);
  ASSERT_EQ(rv2.enc_amounts, rv.enc_amounts);
  ASSERT_EQ(rv2.enc_labels, rv.enc_labels);
  ASSERT_EQ(rv2.outPk.size(), 1u);
  ASSERT_EQ(rv2.outPk[0].mask, rv.outPk[0].mask);
}

// enc_label integrity is prehash-bound (no Pedersen commitment backstop).
// Tampering enc_labels must change serialize_ctsig_base → get_tx_prehash input.
TEST(fcmp, enc_label_binds_ctsig_base_prehash)
{
  ct::CtSig rv;
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  memset(&rv.referenceBlock, 0xCD, sizeof(rv.referenceBlock));
  rv.enc_amounts.resize(1);
  rv.enc_labels.resize(1);
  rv.outPk.resize(1);
  rv.outPk[0].mask = ct::skGen();
  for (size_t i = 0; i < 8; ++i)
  {
    rv.enc_amounts[0][i] = static_cast<uint8_t>(0x10 + i);
    rv.enc_labels[0][i] = static_cast<uint8_t>(0xA0 + i);
  }
  rv.enc_amounts[0][8] = 0x55;
  rv.enc_labels[0][8] = 0x66;

  const crypto::hash h0 = hash_ctsig_base_component(rv);

  rv.enc_labels[0][0] ^= 0x01;
  const crypto::hash h_label_tamper = hash_ctsig_base_component(rv);
  EXPECT_NE(h0, h_label_tamper) << "enc_label byte flip must change CtSigBase prehash component";

  rv.enc_labels[0][0] ^= 0x01;
  rv.enc_amounts[0][0] ^= 0x01;
  const crypto::hash h_amount_tamper = hash_ctsig_base_component(rv);
  EXPECT_NE(h0, h_amount_tamper) << "enc_amount byte flip must change CtSigBase prehash component";
}

TEST(fcmp, CTTypeNull_serialization)
{
  // The real coinbase base encoding (`serialize_ctsig_base`, the only
  // encoding — see the roundtrip test above) for a Null rct with no outputs
  // is exactly the one type byte: no txnFee, no referenceBlock, no legacy
  // pseudo-out material. The full-transaction-level pin lives in
  // tests/unit_tests/serialization.cpp; this is the focused component read.
  ct::CtSig rv;
  rv.type = ct::CTTypeNull;

  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(rv.serialize_ctsig_base(ar, 1, 0));
    blob = oss.str();
  }
  ASSERT_EQ(blob.size(), 1u);
  ASSERT_EQ(blob[0], static_cast<char>(ct::CTTypeNull));

  ct::CtSig rv2;
  {
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(blob.data()), blob.size()});
    ASSERT_TRUE(rv2.serialize_ctsig_base(ar, 1, 0));
  }

  ASSERT_EQ(rv2.type, ct::CTTypeNull);
}

TEST(fcmp, referenceBlock_staleness_constants)
{
  ASSERT_GT(FCMP_REFERENCE_BLOCK_MAX_AGE, FCMP_REFERENCE_BLOCK_MIN_AGE);
  ASSERT_GE((uint64_t)CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, (uint64_t)FCMP_REFERENCE_BLOCK_MIN_AGE);
  ASSERT_GE((uint64_t)CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, (uint64_t)FCMP_REFERENCE_BLOCK_MIN_AGE);
  // FCMP_REFERENCE_BLOCK_MIN_AGE is a reorg margin only; spend maturity uses
  // CRYPTONOTE_*_AGE and deferred curve-tree insertion — it is intentionally below those windows.
}

TEST(fcmp, key_offsets_empty_for_fcmp_type)
{
  // FCMP++ transactions must not have key_offsets (ring members); the
  // membership proof ranges over the full UTXO set via the curve tree, which
  // is the spend's anonymity set since PL-D3 (2026-09-14; before it, PL-D1 —
  // docs/design/FCMP_SPEND_LINKABILITY.md).
  cryptonote::txin_to_key txin;
  txin.key_offsets.clear();
  ASSERT_TRUE(txin.key_offsets.empty());
}

TEST(fcmp, get_pseudo_outs_uses_prunable_for_all_types)
{
  // The pseudo-out commitments live in the prunable section for every rct
  // type (the legacy base-side fallback field was removed in the
  // dead-serializer cleanup): FCMP++ carries one per spend input, and a
  // coinbase (CTTypeNull) has none, so the accessor returns the empty
  // prunable vector there.
  ct::CtSig rv;
  rv.type = ct::CTTypeFcmpPlusPlusPqc;

  ct::key k1 = ct::skGen();
  rv.p.pseudoOuts.push_back(k1);

  const auto &po = rv.get_pseudo_outs();
  ASSERT_EQ(po.size(), 1u);
  ASSERT_EQ(po[0], k1);

  ct::CtSig coinbase;
  coinbase.type = ct::CTTypeNull;
  ASSERT_TRUE(coinbase.get_pseudo_outs().empty());
}

TEST(fcmp, curve_tree_root_in_block_header)
{
  cryptonote::block_header hdr;
  ASSERT_EQ(hdr.curve_tree_root, crypto::null_hash);

  crypto::hash test_root;
  memset(&test_root, 0xBE, sizeof(test_root));
  hdr.curve_tree_root = test_root;
  ASSERT_EQ(hdr.curve_tree_root, test_root);

  // Serialization roundtrip
  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(do_serialize(ar, hdr));
    blob = oss.str();
  }

  cryptonote::block_header hdr2;
  {
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(blob.data()), blob.size()});
    ASSERT_TRUE(do_serialize(ar, hdr2));
  }

  ASSERT_EQ(hdr2.curve_tree_root, test_root);
}

// (The attestation_root default/serialization test lives in
// archival_credit_wire.cpp — it is credit-wire, not FCMP, coverage.)

TEST(fcmp, fcmp_pp_proof_empty_rejected_by_verifier)
{
  ct::CtSig rv;
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.p.fcmp_pp_proof.clear();
  rv.p.curve_trees_tree_depth = 20;

  // verCtSemanticsSimple should reject empty proof
  ASSERT_FALSE(ct::verCtSemanticsSimple(rv));
}

// ---------------------------------------------------------------------------
// FCMP++ PQC Multisig Integration Tests
// ---------------------------------------------------------------------------

#include "shekyl/shekyl_ffi.h"
#include "rapidjson/document.h"
#include "string_tools.h"

TEST(fcmp, multisig_signing_request_json_v2_fields)
{
  // Verify that the v2 signing request JSON contains all required FCMP++ fields.
  // We construct a minimal JSON document mimicking the format and verify its
  // structure without needing a full wallet instance.
  rapidjson::Document doc;
  doc.SetObject();
  auto& a = doc.GetAllocator();

  doc.AddMember("version", 2, a);
  doc.AddMember("n_total", 3, a);
  doc.AddMember("m_required", 2, a);
  doc.AddMember("payload_hash", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", a);
  doc.AddMember("tx_blob", "deadbeef", a);
  doc.AddMember("fcmp_proof", "cafebabe", a);
  doc.AddMember("reference_block", "1111111111111111111111111111111111111111111111111111111111111111", a);
  doc.AddMember("tree_depth", 20, a);

  rapidjson::Value pqc_arr(rapidjson::kArrayType);
  pqc_arr.PushBack("aabb", a);
  pqc_arr.PushBack("ccdd", a);
  doc.AddMember("per_input_pqc_pubkeys", pqc_arr, a);

  rapidjson::Value idx_arr(rapidjson::kArrayType);
  idx_arr.PushBack(100u, a);
  idx_arr.PushBack(200u, a);
  doc.AddMember("input_global_indices", idx_arr, a);

  ASSERT_TRUE(doc.HasMember("version"));
  ASSERT_EQ(doc["version"].GetInt(), 2);
  ASSERT_TRUE(doc.HasMember("fcmp_proof"));
  ASSERT_TRUE(doc.HasMember("reference_block"));
  ASSERT_TRUE(doc.HasMember("tree_depth"));
  ASSERT_EQ(doc["tree_depth"].GetInt(), 20);
  ASSERT_TRUE(doc.HasMember("per_input_pqc_pubkeys"));
  ASSERT_TRUE(doc["per_input_pqc_pubkeys"].IsArray());
  ASSERT_EQ(doc["per_input_pqc_pubkeys"].Size(), 2u);
  ASSERT_TRUE(doc.HasMember("input_global_indices"));
  ASSERT_TRUE(doc["input_global_indices"].IsArray());
  ASSERT_EQ(doc["input_global_indices"].Size(), 2u);
}

TEST(fcmp, per_output_pqc_leaf_derivation_consistency)
{
  uint8_t combined_ss[64];
  crypto::rand(64, combined_ss);

  // 64-byte 0x07 entries: CM || record (PL-D3 / PL-D3a).
  uint8_t h1[64], h2[64], h3[64];
  ASSERT_TRUE(shekyl_derive_pqc_leaf_entry(combined_ss, 42, h1));
  ASSERT_TRUE(shekyl_derive_pqc_leaf_entry(combined_ss, 42, h2));
  ASSERT_EQ(memcmp(h1, h2, 64), 0) << "Same input must produce the same leaf entry";

  ASSERT_TRUE(shekyl_derive_pqc_leaf_entry(combined_ss, 99, h3));
  ASSERT_NE(memcmp(h1, h3, 32), 0) << "Different index must produce a different commitment";
  ASSERT_NE(memcmp(h1 + 32, h3 + 32, 32), 0) << "Different index must produce a different record";
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 7: Timestamp unlock_time rejection (D13) - unit level
// ═══════════════════════════════════════════════════════════════════════════

TEST(fcmp, timestamp_unlock_time_sentinel_constant)
{
  // CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL must equal CRYPTONOTE_MAX_BLOCK_NUMBER
  ASSERT_EQ(CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL, CRYPTONOTE_MAX_BLOCK_NUMBER);
  // Sentinel marks "timestamp unlock" in unlock_time; must not collide with a real height.
  ASSERT_GE(CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL, 500000000ULL);
}

TEST(fcmp, fcmp_reference_block_min_age_value)
{
  ASSERT_EQ(FCMP_REFERENCE_BLOCK_MIN_AGE, 5u);
  ASSERT_LT(FCMP_REFERENCE_BLOCK_MIN_AGE, FCMP_REFERENCE_BLOCK_MAX_AGE);
}
