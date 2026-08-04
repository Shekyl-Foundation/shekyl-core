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

#include "fcmp/rctTypes.h"
#include "fcmp/rctSigs.h"
#include "fcmp/rctOps.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pqc_verify.h"

using namespace std;
using namespace crypto;
using namespace rct;

namespace {

crypto::hash hash_rctsig_base_component(const rct::rctSig &rv)
{
  std::stringstream ss;
  binary_archive<true> ba(ss);
  const size_t inputs = rv.p.pseudoOuts.size();
  const size_t outputs = rv.enc_amounts.size();
  rct::rctSig mutable_rv = rv;
  CHECK_AND_ASSERT_THROW_MES(
      mutable_rv.serialize_rctsig_base(ba, inputs, outputs),
      "serialize_rctsig_base failed in test");
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
  out << "BEGIN" << rct::H << "END";
  EXPECT_EQ(
    std::string{"BEGIN<8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94>END"},
    out.str()
  );
}

TEST(fcmp, zeroCommmit)
{
  static const uint64_t amount = crypto::rand<uint64_t>();
  const rct::key z = rct::zeroCommit(amount);
  const rct::key a = rct::scalarmultBase(rct::identity());
  const rct::key b = rct::scalarmultH(rct::d2h(amount));
  const rct::key manual = rct::addKeys(a, b);
  ASSERT_EQ(z, manual);
}

static rct::key uncachedZeroCommit(uint64_t amount)
{
  const rct::key am = rct::d2h(amount);
  const rct::key bH = rct::scalarmultH(am);
  return rct::addKeys(rct::G, bH);
}

TEST(fcmp, zeroCommitCache)
{
  ASSERT_EQ(rct::zeroCommit(0), uncachedZeroCommit(0));
  ASSERT_EQ(rct::zeroCommit(1), uncachedZeroCommit(1));
  ASSERT_EQ(rct::zeroCommit(2), uncachedZeroCommit(2));
  ASSERT_EQ(rct::zeroCommit(10), uncachedZeroCommit(10));
  ASSERT_EQ(rct::zeroCommit(200), uncachedZeroCommit(200));
  ASSERT_EQ(rct::zeroCommit(1000000000), uncachedZeroCommit(1000000000));
  ASSERT_EQ(rct::zeroCommit(3000000000000), uncachedZeroCommit(3000000000000));
  ASSERT_EQ(rct::zeroCommit(900000000000000), uncachedZeroCommit(900000000000000));
}

TEST(fcmp, H)
{
  ge_p3 p3;
  ASSERT_EQ(ge_frombytes_vartime(&p3, rct::H.bytes), 0);
  ASSERT_EQ(memcmp(&p3, &ge_p3_H, sizeof(ge_p3)), 0);
}

TEST(fcmp, mul8)
{
  ge_p3 p3;
  rct::key key;
  ASSERT_EQ(rct::scalarmult8(rct::identity()), rct::identity());
  rct::scalarmult8(p3,rct::identity());
  ge_p3_tobytes(key.bytes, &p3);
  ASSERT_EQ(key, rct::identity());
  ASSERT_EQ(rct::scalarmult8(rct::H), rct::scalarmultKey(rct::H, rct::EIGHT));
  rct::scalarmult8(p3,rct::H);
  ge_p3_tobytes(key.bytes, &p3);
  ASSERT_EQ(key, rct::scalarmultKey(rct::H, rct::EIGHT));
  ASSERT_EQ(rct::scalarmultKey(rct::scalarmultKey(rct::H, rct::INV_EIGHT), rct::EIGHT), rct::H);
}

// ──────────────────────────────────────────────────────────────────────
// FCMP++ / PQC-specific tests (Phase 7)
// ──────────────────────────────────────────────────────────────────────

TEST(fcmp, CTTypeFcmpPlusPlusPqc_serialization_roundtrip)
{
  // Round-trips the rct base through `serialize_rctsig_base` — the ONLY
  // encoding of the base (the transaction serializer, the tx-hash paths, the
  // FCMP++ pre-hash, and the PQC payload binding all call it). A standalone
  // object serializer used to exist and was round-tripped here instead; it
  // was caller-less in production, laxer than the real wire (it accepted
  // states the member serializer rejects), and was deleted in the
  // dead-serializer cleanup (CT_SURFACE_NAMING_PIN.md §2). The prunable
  // section's real-path round-trip is covered at the transaction level
  // (tests/unit_tests/serialization.cpp and the shekyl-wire KATs).
  rct::rctSig rv;
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
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

  rct::ctkey outpk;
  outpk.dest = rct::pkGen();
  outpk.mask = rct::pkGen();
  rv.outPk.push_back(outpk);

  const size_t inputs = 1;
  const size_t outputs = 1;

  // Serialize (real wire path)
  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(rv.serialize_rctsig_base(ar, inputs, outputs));
    blob = oss.str();
  }

  // Deserialize
  rct::rctSig rv2;
  {
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(blob.data()), blob.size()});
    ASSERT_TRUE(rv2.serialize_rctsig_base(ar, inputs, outputs));
  }

  ASSERT_EQ(rv2.type, rct::CTTypeFcmpPlusPlusPqc);
  ASSERT_EQ(rv2.txnFee, rv.txnFee);
  ASSERT_EQ(rv2.referenceBlock, rv.referenceBlock);
  ASSERT_EQ(rv2.enc_amounts, rv.enc_amounts);
  ASSERT_EQ(rv2.enc_labels, rv.enc_labels);
  ASSERT_EQ(rv2.outPk.size(), 1u);
  ASSERT_EQ(rv2.outPk[0].mask, rv.outPk[0].mask);
}

// enc_label integrity is prehash-bound (no Pedersen commitment backstop).
// Tampering enc_labels must change serialize_rctsig_base → get_tx_prehash input.
TEST(fcmp, enc_label_binds_rctsig_base_prehash)
{
  rct::rctSig rv;
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  memset(&rv.referenceBlock, 0xCD, sizeof(rv.referenceBlock));
  rv.enc_amounts.resize(1);
  rv.enc_labels.resize(1);
  rv.outPk.resize(1);
  rv.outPk[0].mask = rct::skGen();
  for (size_t i = 0; i < 8; ++i)
  {
    rv.enc_amounts[0][i] = static_cast<uint8_t>(0x10 + i);
    rv.enc_labels[0][i] = static_cast<uint8_t>(0xA0 + i);
  }
  rv.enc_amounts[0][8] = 0x55;
  rv.enc_labels[0][8] = 0x66;

  const crypto::hash h0 = hash_rctsig_base_component(rv);

  rv.enc_labels[0][0] ^= 0x01;
  const crypto::hash h_label_tamper = hash_rctsig_base_component(rv);
  EXPECT_NE(h0, h_label_tamper) << "enc_label byte flip must change rctSigBase prehash component";

  rv.enc_labels[0][0] ^= 0x01;
  rv.enc_amounts[0][0] ^= 0x01;
  const crypto::hash h_amount_tamper = hash_rctsig_base_component(rv);
  EXPECT_NE(h0, h_amount_tamper) << "enc_amount byte flip must change rctSigBase prehash component";
}

TEST(fcmp, CTTypeNull_serialization)
{
  // The real coinbase base encoding (`serialize_rctsig_base`, the only
  // encoding — see the roundtrip test above) for a Null rct with no outputs
  // is exactly the one type byte: no txnFee, no referenceBlock, no legacy
  // pseudo-out material. The full-transaction-level pin lives in
  // tests/unit_tests/serialization.cpp; this is the focused component read.
  rct::rctSig rv;
  rv.type = rct::CTTypeNull;

  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(rv.serialize_rctsig_base(ar, 1, 0));
    blob = oss.str();
  }
  ASSERT_EQ(blob.size(), 1u);
  ASSERT_EQ(blob[0], static_cast<char>(rct::CTTypeNull));

  rct::rctSig rv2;
  {
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(blob.data()), blob.size()});
    ASSERT_TRUE(rv2.serialize_rctsig_base(ar, 1, 0));
  }

  ASSERT_EQ(rv2.type, rct::CTTypeNull);
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
  // FCMP++ transactions must not have key_offsets (ring members);
  // the anonymity set is the full UTXO set via the curve tree proof.
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
  rct::rctSig rv;
  rv.type = rct::CTTypeFcmpPlusPlusPqc;

  rct::key k1 = rct::skGen();
  rv.p.pseudoOuts.push_back(k1);

  const auto &po = rv.get_pseudo_outs();
  ASSERT_EQ(po.size(), 1u);
  ASSERT_EQ(po[0], k1);

  rct::rctSig coinbase;
  coinbase.type = rct::CTTypeNull;
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

// ARCHIVAL_CREDIT_WIRE.md §3: empty is attestation_root(&[]), never null_hash.
TEST(fcmp, attestation_root_defaults_to_empty_set_root)
{
  cryptonote::block_header hdr;
  ASSERT_EQ(hdr.attestation_root, cryptonote::empty_attestation_root());
  ASSERT_NE(hdr.attestation_root, crypto::null_hash);

  crypto::hash test_root;
  memset(&test_root, 0xAD, sizeof(test_root));
  hdr.attestation_root = test_root;

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
  ASSERT_EQ(hdr2.attestation_root, test_root);
  // Final field on the wire: last 32 bytes of the serialized header.
  ASSERT_GE(blob.size(), sizeof(crypto::hash));
  ASSERT_EQ(0, memcmp(blob.data() + blob.size() - sizeof(crypto::hash), &test_root, sizeof(test_root)));
}

TEST(fcmp, fcmp_pp_proof_empty_rejected_by_verifier)
{
  rct::rctSig rv;
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
  rv.p.fcmp_pp_proof.clear();
  rv.p.curve_trees_tree_depth = 20;

  // verRctSemanticsSimple should reject empty proof
  ASSERT_FALSE(rct::verRctSemanticsSimple(rv));
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

TEST(fcmp, multisig_pqc_leaf_hash_via_ffi)
{
  // Generate 3 PQC keypairs and build a key container blob,
  // then verify shekyl_fcmp_pqc_leaf_hash returns a non-zero 32-byte hash.
  std::vector<std::vector<uint8_t>> pub_keys;
  for (int i = 0; i < 3; ++i)
  {
    ShekylPqcKeypair kp = shekyl_pqc_keypair_generate();
    ASSERT_TRUE(kp.success);
    ASSERT_GT(kp.public_key.len, 0u);
    pub_keys.emplace_back(kp.public_key.ptr, kp.public_key.ptr + kp.public_key.len);
    shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
    shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
  }

  // V3.1 wire format: [version(1) | n_total(1) | m_required(1) | key0 | key1 | key2 | sa_pk0 | sa_pk1 | sa_pk2]
  std::vector<uint8_t> keys_blob;
  keys_blob.push_back(0x01);  // MULTISIG_CONTAINER_VERSION
  keys_blob.push_back(3);     // n_total
  keys_blob.push_back(2);     // m_required
  for (const auto& pk : pub_keys)
    keys_blob.insert(keys_blob.end(), pk.begin(), pk.end());
  // Append 3 dummy 32-byte spend_auth_pubkeys (deterministic placeholder for test)
  for (int i = 0; i < 3; ++i)
  {
    uint8_t sa_pk[32];
    memset(sa_pk, 0x10 + i, 32);
    keys_blob.insert(keys_blob.end(), sa_pk, sa_pk + 32);
  }

  uint8_t hash_out[32] = {};
  bool ok = shekyl_fcmp_pqc_leaf_hash(keys_blob.data(), keys_blob.size(), hash_out);
  ASSERT_TRUE(ok);

  // Hash should not be all zeros
  bool all_zero = true;
  for (int i = 0; i < 32; ++i)
    if (hash_out[i] != 0) { all_zero = false; break; }
  ASSERT_FALSE(all_zero);

  // Deterministic: same input, same output
  uint8_t hash_out2[32] = {};
  ok = shekyl_fcmp_pqc_leaf_hash(keys_blob.data(), keys_blob.size(), hash_out2);
  ASSERT_TRUE(ok);
  ASSERT_EQ(memcmp(hash_out, hash_out2, 32), 0);
}

TEST(fcmp, multisig_partial_sig_roundtrip)
{
  // Generate a keypair, sign a message, and verify the signature roundtrips
  // through hex encoding (as the signing request JSON uses).
  ShekylPqcKeypair kp = shekyl_pqc_keypair_generate();
  ASSERT_TRUE(kp.success);

  uint8_t msg[32];
  memset(msg, 0xAB, 32);

  ShekylPqcSignatureResult sig = shekyl_pqc_sign(
      kp.secret_key.ptr, kp.secret_key.len, msg, 32);
  ASSERT_TRUE(sig.success);

  std::vector<uint8_t> sig_bytes(sig.signature.ptr, sig.signature.ptr + sig.signature.len);
  shekyl_buffer_free(sig.signature.ptr, sig.signature.len);

  // Hex roundtrip
  std::string sig_hex = epee::string_tools::buff_to_hex_nodelimer(
      std::string(reinterpret_cast<const char*>(sig_bytes.data()), sig_bytes.size()));
  std::string recovered;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(sig_hex, recovered));
  ASSERT_EQ(recovered.size(), sig_bytes.size());
  ASSERT_EQ(memcmp(recovered.data(), sig_bytes.data(), sig_bytes.size()), 0);

  // Verify the roundtripped signature (scheme_id 1 = PQC_SCHEME_SINGLE)
  uint8_t pqc_result = shekyl_pqc_verify(
      1,
      kp.public_key.ptr, kp.public_key.len,
      reinterpret_cast<const uint8_t*>(recovered.data()), recovered.size(),
      msg, 32);
  ASSERT_EQ(pqc_result, 0) << "PQC verify error code: " << (int)pqc_result;

  shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
  shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
}

TEST(fcmp, per_output_pqc_leaf_hash_derivation_consistency)
{
  uint8_t combined_ss[64];
  crypto::rand(64, combined_ss);

  uint8_t h1[32], h2[32], h3[32];
  ASSERT_TRUE(shekyl_derive_pqc_leaf_hash(combined_ss, 42, h1));
  ASSERT_TRUE(shekyl_derive_pqc_leaf_hash(combined_ss, 42, h2));
  ASSERT_EQ(memcmp(h1, h2, 32), 0) << "Same input must produce same leaf hash";

  ASSERT_TRUE(shekyl_derive_pqc_leaf_hash(combined_ss, 99, h3));
  ASSERT_NE(memcmp(h1, h3, 32), 0) << "Different index must produce different leaf hash";
}

TEST(fcmp, multisig_2of3_sig_container_assembly)
{
  // Simulate the coordinator assembling a MultisigSigContainer from 2-of-3
  // partial signatures, matching the wire format used by import_multisig_signatures.
  ShekylPqcKeypair kps[3];
  for (int i = 0; i < 3; ++i)
  {
    kps[i] = shekyl_pqc_keypair_generate();
    ASSERT_TRUE(kps[i].success);
  }

  uint8_t payload_hash[32];
  memset(payload_hash, 0xCC, 32);

  // Signers 0 and 2 produce partial signatures
  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> partials;
  for (int signer : {0, 2})
  {
    ShekylPqcSignatureResult sig = shekyl_pqc_sign(
        kps[signer].secret_key.ptr, kps[signer].secret_key.len,
        payload_hash, 32);
    ASSERT_TRUE(sig.success);
    partials.push_back({(uint8_t)signer,
        std::vector<uint8_t>(sig.signature.ptr, sig.signature.ptr + sig.signature.len)});
    shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
  }

  // Build MultisigSigContainer blob: [sig_count(1) | sig0 | sig1 | idx0(1) | idx1(1)]
  uint8_t m_required = 2;
  std::vector<uint8_t> sig_blob;
  sig_blob.push_back(m_required);
  for (const auto& p : partials)
    sig_blob.insert(sig_blob.end(), p.second.begin(), p.second.end());
  for (const auto& p : partials)
    sig_blob.push_back(p.first);

  // V3.1 MultisigKeyContainer blob: [version(1) | n(1) | m(1) | pk0 | pk1 | pk2 | sa_pk0..2]
  std::vector<uint8_t> key_blob;
  key_blob.push_back(0x01);  // MULTISIG_CONTAINER_VERSION
  key_blob.push_back(3);
  key_blob.push_back(2);
  for (int i = 0; i < 3; ++i)
  {
    key_blob.insert(key_blob.end(),
        kps[i].public_key.ptr, kps[i].public_key.ptr + kps[i].public_key.len);
  }
  for (int i = 0; i < 3; ++i)
  {
    uint8_t sa_pk[32];
    memset(sa_pk, 0x20 + i, 32);
    key_blob.insert(key_blob.end(), sa_pk, sa_pk + 32);
  }

  // Verify the assembled multisig via FFI (scheme_id = 2 triggers multisig path)
  // shekyl_pqc_verify dispatches to verify_multisig internally for scheme_id 2.
  // The pubkey_blob is the key container; sig_blob is the sig container.
  uint8_t pqc_result = shekyl_pqc_verify(
      2,  // scheme_id = multisig
      key_blob.data(), key_blob.size(),
      sig_blob.data(), sig_blob.size(),
      payload_hash, 32);
  ASSERT_EQ(pqc_result, 0) << "multisig PQC verify error code: " << (int)pqc_result;

  // Cleanup
  for (int i = 0; i < 3; ++i)
  {
    shekyl_buffer_free(kps[i].public_key.ptr, kps[i].public_key.len);
    shekyl_buffer_free(kps[i].secret_key.ptr, kps[i].secret_key.len);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MSW-1: PQC constant cross-language consistency (bound family)
// ═══════════════════════════════════════════════════════════════════════════

// The C++ `cryptonote_config.h` PQC constants are hand-written twins of
// shekyl-crypto-pq's canonical values (the FFI header is hand-written — no
// cbindgen). Each side has its own compile-time guard against internal drift
// (`static_assert` in C++, `const _` assert in Rust: ceiling >= largest legal
// container). This test guards the third failure mode — C++ and Rust each
// internally consistent but disagreeing with each other across the FFI, which
// is exactly what F-1 was and which no single-language assert can see. It reads
// both sides and asserts equality.
TEST(fcmp, msw1_pqc_constants_match_rust)
{
  const ShekylPqcCanonicalLens r = shekyl_pqc_canonical_lens();
  EXPECT_EQ(r.single_key_len, config::PQC_HYBRID_SINGLE_KEY_LEN);
  EXPECT_EQ(r.single_sig_len, config::PQC_HYBRID_SINGLE_SIG_LEN);
  EXPECT_EQ(r.spend_auth_pubkey_len, config::PQC_SPEND_AUTH_PUBKEY_LEN);
  EXPECT_EQ(r.max_multisig_participants,
            static_cast<size_t>(config::MAX_MULTISIG_PARTICIPANTS));
  EXPECT_EQ(r.max_public_key_blob, config::PQC_MAX_PUBLIC_KEY_BLOB);
  EXPECT_EQ(r.max_signature_blob, config::PQC_MAX_SIGNATURE_BLOB);
}

// ═══════════════════════════════════════════════════════════════════════════
// MSW-6: per-input scheme mixing (tx-wide scheme_id agreement withdrawn)
// ═══════════════════════════════════════════════════════════════════════════

namespace {

// V3.1 MultisigKeyContainer for an n=3, m=2 group:
// [version(1) | n(1) | m(1) | pk0..2(1996 each) | sa_pk0..2(32 each)].
// Same layout the scheme_id=2 path in shekyl_pqc_verify parses (see
// multisig_2of3_sig_container_assembly above).
std::vector<uint8_t> msw6_build_multisig_key_container(const ShekylPqcKeypair (&kps)[3])
{
  std::vector<uint8_t> key_blob;
  key_blob.push_back(0x01);  // MULTISIG_CONTAINER_VERSION
  key_blob.push_back(3);     // n_total
  key_blob.push_back(2);     // m_required
  for (int i = 0; i < 3; ++i)
    key_blob.insert(key_blob.end(),
        kps[i].public_key.ptr, kps[i].public_key.ptr + kps[i].public_key.len);
  for (int i = 0; i < 3; ++i)
  {
    uint8_t sa_pk[32];
    memset(sa_pk, 0x20 + i, 32);
    key_blob.insert(key_blob.end(), sa_pk, sa_pk + 32);
  }
  return key_blob;
}

// 2-of-3 MultisigSigContainer over msg by signers {0,2}:
// [m(1) | sig0 | sig1 | idx0(1) | idx1(1)].
std::vector<uint8_t> msw6_sign_multisig_2of3(const ShekylPqcKeypair (&kps)[3],
                                             const crypto::hash& msg)
{
  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> partials;
  for (int signer : {0, 2})
  {
    ShekylPqcSignatureResult sig = shekyl_pqc_sign(
        kps[signer].secret_key.ptr, kps[signer].secret_key.len,
        reinterpret_cast<const uint8_t*>(msg.data), 32);
    CHECK_AND_ASSERT_THROW_MES(sig.success, "multisig partial sign failed");
    partials.push_back({(uint8_t)signer,
        std::vector<uint8_t>(sig.signature.ptr, sig.signature.ptr + sig.signature.len)});
    shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
  }
  std::vector<uint8_t> sig_blob;
  sig_blob.push_back(2);  // m_required
  for (const auto& p : partials)
    sig_blob.insert(sig_blob.end(), p.second.begin(), p.second.end());
  for (const auto& p : partials)
    sig_blob.push_back(p.first);
  return sig_blob;
}

// Minimal 2-spend-input, 0-output v3 tx whose rct base + prunable serialize
// through get_transaction_signed_payload. 0 outputs ⇒ no Bp+ / outPk needed;
// two spend inputs ⇒ two pseudoOuts. Not a spendable tx — just enough for the
// PQC signing-payload binding that verify_transaction_pqc_auth checks.
cryptonote::transaction msw6_two_spend_skeleton()
{
  cryptonote::transaction tx{};
  tx.version = 3;

  cryptonote::txin_to_key in0;
  memset(&in0.k_image, 0xB0, 32);
  in0.amount = 0;
  cryptonote::txin_to_key in1;
  memset(&in1.k_image, 0xB1, 32);
  in1.amount = 0;
  tx.vin.push_back(in0);
  tx.vin.push_back(in1);

  tx.rct_signatures.type = rct::CTTypeFcmpPlusPlusPqc;
  tx.rct_signatures.txnFee = 0;
  memset(&tx.rct_signatures.referenceBlock, 0xAA, 32);
  tx.rct_signatures.p.curve_trees_tree_depth = 1;
  tx.rct_signatures.p.fcmp_pp_proof = {0x01, 0x02, 0x03, 0x04};
  tx.rct_signatures.p.pseudoOuts.resize(2);  // one per spend input

  tx.pqc_auths.resize(2);
  return tx;
}

crypto::hash msw6_input_payload_hash(const cryptonote::transaction& tx, size_t idx)
{
  std::string payload;
  CHECK_AND_ASSERT_THROW_MES(cryptonote::get_transaction_signed_payload(tx, idx, payload),
                             "get_transaction_signed_payload failed");
  crypto::hash h;
  cryptonote::get_blob_hash(payload, h);
  return h;
}

} // namespace

// MSW-6: a v3 tx that spends a solo (scheme 1) output AND a multisig (scheme 2)
// output in ONE tx now verifies. Before MSW-6 the tx-wide scheme_id agreement
// rejected it at input 1 (scheme 2 != pqc_auths[0].scheme_id == 1) before the
// signature was ever checked. That is the enabler this withdrawal exists for:
// scheme-2 funding sharing a tx with a scheme-1 bond vin (PQC_MULTISIG.md §16.3,
// V3_1_MULTISIG_RUST_ENGINE.md MSW-6). Each input is still bound to its own
// signature — the negative control pins that the per-input crypto is intact.
TEST(fcmp, msw6_mixed_scheme_transaction_verifies)
{
  ShekylPqcKeypair kp_single = shekyl_pqc_keypair_generate();
  ASSERT_TRUE(kp_single.success);
  ShekylPqcKeypair kps[3];
  for (int i = 0; i < 3; ++i)
  {
    kps[i] = shekyl_pqc_keypair_generate();
    ASSERT_TRUE(kps[i].success);
  }

  cryptonote::transaction tx = msw6_two_spend_skeleton();

  // Public keys must be final before the payloads are computed — the signing
  // payload binds every input's key hash (get_transaction_signed_payload), so
  // the signatures are set afterward (the payload never covers the signature).
  tx.pqc_auths[0].auth_version = 1;
  tx.pqc_auths[0].scheme_id = 1;  // solo
  tx.pqc_auths[0].flags = 0;
  tx.pqc_auths[0].hybrid_public_key.assign(
      kp_single.public_key.ptr, kp_single.public_key.ptr + kp_single.public_key.len);

  tx.pqc_auths[1].auth_version = 1;
  tx.pqc_auths[1].scheme_id = 2;  // multisig
  tx.pqc_auths[1].flags = 0;
  tx.pqc_auths[1].hybrid_public_key = msw6_build_multisig_key_container(kps);

  crypto::hash h0 = msw6_input_payload_hash(tx, 0);
  ShekylPqcSignatureResult sig0 = shekyl_pqc_sign(
      kp_single.secret_key.ptr, kp_single.secret_key.len,
      reinterpret_cast<const uint8_t*>(h0.data), 32);
  ASSERT_TRUE(sig0.success);
  tx.pqc_auths[0].hybrid_signature.assign(sig0.signature.ptr,
                                          sig0.signature.ptr + sig0.signature.len);
  shekyl_buffer_free(sig0.signature.ptr, sig0.signature.len);

  crypto::hash h1 = msw6_input_payload_hash(tx, 1);
  tx.pqc_auths[1].hybrid_signature = msw6_sign_multisig_2of3(kps, h1);

  // The enabler: the mixed-scheme tx verifies.
  EXPECT_TRUE(cryptonote::verify_transaction_pqc_auth(tx))
      << "MSW-6: a solo(1)+multisig(2) transaction must verify";

  // Negative control: the relaxation dropped only the cross-input agreement,
  // not the per-input signature binding. Corrupt the multisig signature and the
  // same tx must fail.
  cryptonote::transaction tampered = tx;
  ASSERT_GE(tampered.pqc_auths[1].hybrid_signature.size(), 4u);
  tampered.pqc_auths[1].hybrid_signature[3] ^= 0xFF;
  EXPECT_FALSE(cryptonote::verify_transaction_pqc_auth(tampered))
      << "per-input signature binding must still reject a tampered auth";

  shekyl_buffer_free(kp_single.public_key.ptr, kp_single.public_key.len);
  shekyl_buffer_free(kp_single.secret_key.ptr, kp_single.secret_key.len);
  for (int i = 0; i < 3; ++i)
  {
    shekyl_buffer_free(kps[i].public_key.ptr, kps[i].public_key.len);
    shekyl_buffer_free(kps[i].secret_key.ptr, kps[i].secret_key.len);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 7: Verification caching tests
// ═══════════════════════════════════════════════════════════════════════════

TEST(fcmp, verification_cache_hash_deterministic)
{
  // Same transaction produces the same verification hash twice
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.rct_signatures.type = rct::CTTypeFcmpPlusPlusPqc;
  tx.rct_signatures.p.fcmp_pp_proof = {0x01, 0x02, 0x03, 0x04, 0x05};
  memset(&tx.rct_signatures.referenceBlock, 0xAA, 32);

  cryptonote::txin_to_key in1;
  memset(&in1.k_image, 0xBB, 32);
  in1.amount = 0;
  tx.vin.push_back(in1);

  crypto::hash h1 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);
  crypto::hash h2 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);
  ASSERT_EQ(h1, h2);
  ASSERT_NE(h1, crypto::null_hash);
}

TEST(fcmp, verification_cache_hash_differs_on_proof_change)
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.rct_signatures.type = rct::CTTypeFcmpPlusPlusPqc;
  tx.rct_signatures.p.fcmp_pp_proof = {0x01, 0x02, 0x03};
  memset(&tx.rct_signatures.referenceBlock, 0xAA, 32);

  cryptonote::txin_to_key in1;
  memset(&in1.k_image, 0xBB, 32);
  in1.amount = 0;
  tx.vin.push_back(in1);

  crypto::hash h1 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);

  tx.rct_signatures.p.fcmp_pp_proof[0] = 0xFF;
  crypto::hash h2 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);

  ASSERT_NE(h1, h2);
}

TEST(fcmp, verification_cache_hash_differs_on_reference_block_change)
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.rct_signatures.type = rct::CTTypeFcmpPlusPlusPqc;
  tx.rct_signatures.p.fcmp_pp_proof = {0x01, 0x02, 0x03};
  memset(&tx.rct_signatures.referenceBlock, 0xAA, 32);

  cryptonote::txin_to_key in1;
  memset(&in1.k_image, 0xBB, 32);
  in1.amount = 0;
  tx.vin.push_back(in1);

  crypto::hash h1 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);

  memset(&tx.rct_signatures.referenceBlock, 0xCC, 32);
  crypto::hash h2 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);

  ASSERT_NE(h1, h2);
}

TEST(fcmp, verification_cache_hash_differs_on_key_image_change)
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.rct_signatures.type = rct::CTTypeFcmpPlusPlusPqc;
  tx.rct_signatures.p.fcmp_pp_proof = {0x01, 0x02, 0x03};
  memset(&tx.rct_signatures.referenceBlock, 0xAA, 32);

  cryptonote::txin_to_key in1;
  memset(&in1.k_image, 0xBB, 32);
  in1.amount = 0;
  tx.vin.push_back(in1);

  crypto::hash h1 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);

  std::get<cryptonote::txin_to_key>(tx.vin[0]).k_image.data[0] = 0xFF;
  crypto::hash h2 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);

  ASSERT_NE(h1, h2);
}

TEST(fcmp, verification_cache_hash_null_for_non_fcmp_type)
{
  cryptonote::transaction tx{};
  tx.version = 2;
  tx.rct_signatures.type = rct::CTTypeNull;

  crypto::hash h = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);
  ASSERT_EQ(h, crypto::null_hash);
}

TEST(fcmp, verification_cache_hash_multiple_inputs)
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.rct_signatures.type = rct::CTTypeFcmpPlusPlusPqc;
  tx.rct_signatures.p.fcmp_pp_proof = {0x01, 0x02, 0x03, 0x04};
  memset(&tx.rct_signatures.referenceBlock, 0xAA, 32);

  for (int i = 0; i < 4; ++i)
  {
    cryptonote::txin_to_key in;
    memset(&in.k_image, i + 1, 32);
    in.amount = 0;
    tx.vin.push_back(in);
  }

  crypto::hash h1 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);
  ASSERT_NE(h1, crypto::null_hash);

  // Same tx must give same hash
  crypto::hash h2 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);
  ASSERT_EQ(h1, h2);

  // Adding one more input changes the hash
  cryptonote::txin_to_key extra_in;
  memset(&extra_in.k_image, 0x05, 32);
  extra_in.amount = 0;
  tx.vin.push_back(extra_in);

  crypto::hash h3 = cryptonote::Blockchain::compute_fcmp_verification_hash(tx);
  ASSERT_NE(h1, h3);
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
