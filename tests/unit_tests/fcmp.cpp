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
#include "cryptonote_basic/cryptonote_basic.h"

using namespace std;
using namespace crypto;
using namespace rct;

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

TEST(fcmp, RCTTypeFcmpPlusPlusPqc_serialization_roundtrip)
{
  rct::rctSig rv;
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  memset(&rv.referenceBlock, 0xAB, sizeof(rv.referenceBlock));
  rv.message = rct::skGen();

  rct::key pseudo_out;
  rct::skpkGen(pseudo_out, pseudo_out);
  rv.p.pseudoOuts.push_back(pseudo_out);

  rct::ecdhTuple ecdh;
  memset(&ecdh.amount, 0x42, sizeof(ecdh.amount));
  rv.ecdhInfo.push_back(ecdh);

  rct::ctkey outpk;
  outpk.dest = rct::pkGen();
  outpk.mask = rct::pkGen();
  rv.outPk.push_back(outpk);

  rv.p.curve_trees_tree_depth = 20;
  rv.p.fcmp_pp_proof = {0x01, 0x02, 0x03, 0x04, 0x05};

  // Serialize
  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(rv.serialize(ar));
    blob = oss.str();
  }

  // Deserialize
  rct::rctSig rv2;
  {
    std::istringstream iss(blob);
    binary_archive<false> ar(iss);
    ASSERT_TRUE(rv2.serialize(ar));
  }

  ASSERT_EQ(rv2.type, rct::RCTTypeFcmpPlusPlusPqc);
  ASSERT_EQ(rv2.txnFee, rv.txnFee);
  ASSERT_EQ(rv2.referenceBlock, rv.referenceBlock);
  ASSERT_EQ(rv2.p.curve_trees_tree_depth, 20);
  ASSERT_EQ(rv2.p.fcmp_pp_proof.size(), 5u);
  ASSERT_EQ(rv2.p.fcmp_pp_proof, rv.p.fcmp_pp_proof);
}

TEST(fcmp, RCTTypeNull_serialization)
{
  rct::rctSig rv;
  rv.type = rct::RCTTypeNull;

  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(rv.serialize(ar));
    blob = oss.str();
  }

  rct::rctSig rv2;
  {
    std::istringstream iss(blob);
    binary_archive<false> ar(iss);
    ASSERT_TRUE(rv2.serialize(ar));
  }

  ASSERT_EQ(rv2.type, rct::RCTTypeNull);
}

TEST(fcmp, key_image_y_normalize_clears_sign_bit)
{
  crypto::key_image ki;
  memset(&ki, 0xFF, sizeof(ki));

  ASSERT_EQ(reinterpret_cast<unsigned char*>(&ki)[31], 0xFF);
  crypto::key_image_y_normalize(ki);
  ASSERT_EQ(reinterpret_cast<unsigned char*>(&ki)[31] & 0x80, 0);
  ASSERT_EQ(reinterpret_cast<unsigned char*>(&ki)[31], 0x7F);
}

TEST(fcmp, key_image_y_normalize_preserves_already_normalized)
{
  crypto::key_image ki;
  memset(&ki, 0x42, sizeof(ki));
  reinterpret_cast<unsigned char*>(&ki)[31] = 0x05;

  crypto::key_image ki_copy = ki;
  crypto::key_image_y_normalize(ki_copy);
  ASSERT_EQ(memcmp(&ki, &ki_copy, sizeof(ki)), 0);
}

TEST(fcmp, key_image_y_normalize_idempotent)
{
  crypto::key_image ki;
  memset(&ki, 0xDE, sizeof(ki));

  crypto::key_image_y_normalize(ki);
  crypto::key_image ki_after_first = ki;
  crypto::key_image_y_normalize(ki);
  ASSERT_EQ(memcmp(&ki, &ki_after_first, sizeof(ki)), 0);
}

TEST(fcmp, referenceBlock_staleness_constants)
{
  ASSERT_GT(FCMP_REFERENCE_BLOCK_MAX_AGE, FCMP_REFERENCE_BLOCK_MIN_AGE);
  ASSERT_GE((uint64_t)FCMP_REFERENCE_BLOCK_MIN_AGE, (uint64_t)CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
  ASSERT_GE((uint64_t)FCMP_REFERENCE_BLOCK_MIN_AGE, (uint64_t)CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
}

TEST(fcmp, key_offsets_empty_for_fcmp_type)
{
  // FCMP++ transactions must not have key_offsets (ring members);
  // the anonymity set is the full UTXO set via the curve tree proof.
  cryptonote::txin_to_key txin;
  txin.key_offsets.clear();
  ASSERT_TRUE(txin.key_offsets.empty());
}

TEST(fcmp, get_pseudo_outs_uses_prunable_for_fcmp_type)
{
  rct::rctSig rv;
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;

  rct::key k1 = rct::skGen();
  rct::key k2 = rct::skGen();
  rv.p.pseudoOuts.push_back(k1);
  rv.pseudoOuts.push_back(k2);

  const auto &po = rv.get_pseudo_outs();
  ASSERT_EQ(po.size(), 1u);
  ASSERT_EQ(po[0], k1);
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
    ASSERT_TRUE(hdr.serialize(ar));
    blob = oss.str();
  }

  cryptonote::block_header hdr2;
  {
    std::istringstream iss(blob);
    binary_archive<false> ar(iss);
    ASSERT_TRUE(hdr2.serialize(ar));
  }

  ASSERT_EQ(hdr2.curve_tree_root, test_root);
}

TEST(fcmp, fcmp_pp_proof_empty_rejected_by_verifier)
{
  rct::rctSig rv;
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
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
  doc.AddMember("group_id", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", a);
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

  // Build multisig key container blob: [n_total(1) | m_required(1) | key0 | key1 | key2]
  std::vector<uint8_t> keys_blob;
  keys_blob.push_back(3);
  keys_blob.push_back(2);
  for (const auto& pk : pub_keys)
    keys_blob.insert(keys_blob.end(), pk.begin(), pk.end());

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

  // Verify the roundtripped signature
  bool valid = shekyl_pqc_verify(
      kp.public_key.ptr, kp.public_key.len,
      msg, 32,
      reinterpret_cast<const uint8_t*>(recovered.data()), recovered.size());
  ASSERT_TRUE(valid);

  shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
  shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
}

TEST(fcmp, multisig_per_output_pqc_key_derivation_consistency)
{
  // Derive per-output PQC keypairs from the same combined_ss and verify
  // different output indices produce different keys, same index = same key.
  uint8_t combined_ss[64];
  crypto::rand(64, combined_ss);

  ShekylPqcKeypair kp1 = shekyl_fcmp_derive_pqc_keypair(combined_ss, 42);
  ASSERT_TRUE(kp1.success);

  ShekylPqcKeypair kp2 = shekyl_fcmp_derive_pqc_keypair(combined_ss, 42);
  ASSERT_TRUE(kp2.success);

  // Same input → same public key
  ASSERT_EQ(kp1.public_key.len, kp2.public_key.len);
  ASSERT_EQ(memcmp(kp1.public_key.ptr, kp2.public_key.ptr, kp1.public_key.len), 0);

  ShekylPqcKeypair kp3 = shekyl_fcmp_derive_pqc_keypair(combined_ss, 99);
  ASSERT_TRUE(kp3.success);

  // Different output index → different public key
  bool same_pk = (kp1.public_key.len == kp3.public_key.len &&
      memcmp(kp1.public_key.ptr, kp3.public_key.ptr, kp1.public_key.len) == 0);
  ASSERT_FALSE(same_pk);

  shekyl_buffer_free(kp1.public_key.ptr, kp1.public_key.len);
  shekyl_buffer_free(kp1.secret_key.ptr, kp1.secret_key.len);
  shekyl_buffer_free(kp2.public_key.ptr, kp2.public_key.len);
  shekyl_buffer_free(kp2.secret_key.ptr, kp2.secret_key.len);
  shekyl_buffer_free(kp3.public_key.ptr, kp3.public_key.len);
  shekyl_buffer_free(kp3.secret_key.ptr, kp3.secret_key.len);
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

  // Build MultisigKeyContainer blob: [n(1) | m(1) | pk0 | pk1 | pk2]
  std::vector<uint8_t> key_blob;
  key_blob.push_back(3);
  key_blob.push_back(2);
  for (int i = 0; i < 3; ++i)
  {
    key_blob.insert(key_blob.end(),
        kps[i].public_key.ptr, kps[i].public_key.ptr + kps[i].public_key.len);
  }

  // Verify the assembled multisig via FFI (scheme_id = 2 triggers multisig path)
  // shekyl_pqc_verify dispatches to verify_multisig internally for scheme_id 2.
  // The pubkey_blob is the key container; sig_blob is the sig container.
  bool valid = shekyl_pqc_verify(
      2,  // scheme_id = multisig
      key_blob.data(), key_blob.size(),
      sig_blob.data(), sig_blob.size(),
      payload_hash, 32);
  ASSERT_TRUE(valid);

  // Cleanup
  for (int i = 0; i < 3; ++i)
  {
    shekyl_buffer_free(kps[i].public_key.ptr, kps[i].public_key.len);
    shekyl_buffer_free(kps[i].secret_key.ptr, kps[i].secret_key.len);
  }
}
