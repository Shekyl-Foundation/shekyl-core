// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Cross-language KAT for the PRUNED transaction identity -- the 4-part
// FCMP++/PQC spend arm of `get_pruned_transaction_hash` against shekyl-wire's
// `Transaction::hash_with_supplied_prunable` (RK-4c).
//
// RK-4c made the pruned identity a trust boundary: the Rust engine recomputes
// it from an untrusted daemon's bytes and refuses any body whose identity is
// not the requested txid. Before this file, every Rust test derived its
// expected txid from the function under test, so both sides of that check
// could agree on the same wrong value while every real daemon reply got
// refused. This leg breaks the circle: shekyl-wire authored the fixture
// (`pruned_tx_hash_parity_v1.json` -- full bytes, pruned bytes, prunable
// digest, txid), and C++ must reproduce all four with the production
// serializer and hash functions:
//
//   - the same transaction, built field-by-field, serializes to `tx_hex`;
//   - `get_transaction_hash` and `get_pruned_transaction_hash(t, digest)`
//     both produce `tx_hash_hex` (the 4-part {prefix, base, pqc_auths,
//     prunable} mix -- format_utils.cpp:1163-1182);
//   - `calculate_transaction_prunable_hash` produces `prunable_hash_hex`;
//   - `serialize_base` -- the framing `get_pruned_tx_blob` reassembles from
//     `txs_pruned` + `txs_pqc_auths` and the daemon serves as
//     `pruned_as_hex` -- produces `pruned_hex`, a prefix of `tx_hex`.
//
// Structurally parseable, not cryptographically valid: proof bytes are
// zeroed. The one constraint inherited from `expand_transaction_1` is that
// output commitments must decompress (they are multiplied by INV_EIGHT on
// parse), so the fixture uses the compressed Ed25519 basepoint -- the same
// device as `tx_prunable_region_sole_occupant.cpp`.

#include "gtest/gtest.h"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"
#include "string_tools.h"

#ifndef PRUNED_TX_HASH_PARITY_FIXTURE_PATH
#define PRUNED_TX_HASH_PARITY_FIXTURE_PATH \
  "rust/shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json"
#endif

using namespace cryptonote;

namespace {

struct PrunedHashKat {
  std::string tx_hex;
  std::string pruned_hex;
  std::string prunable_hash_hex;
  std::string tx_hash_hex;
};

PrunedHashKat load_kat()
{
  std::ifstream ifs(PRUNED_TX_HASH_PARITY_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing pruned-hash parity fixture at ") + PRUNED_TX_HASH_PARITY_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("tx_hex"))
    throw std::runtime_error("invalid pruned-hash parity fixture");
  PrunedHashKat k{};
  k.tx_hex = doc["tx_hex"].GetString();
  k.pruned_hex = doc["pruned_hex"].GetString();
  k.prunable_hash_hex = doc["prunable_hash_hex"].GetString();
  k.tx_hash_hex = doc["tx_hash_hex"].GetString();
  return k;
}

// The fixture's spend, mirrored from the Rust leg's `build_tx`
// (shekyl-wire/tests/pruned_tx_hash_parity.rs) field by field.
transaction build_kat_tx()
{
  transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;

  txin_to_key txin{};
  txin.amount = 0;
  memset(&txin.k_image, 0x42, sizeof(txin.k_image));
  tx.vin.push_back(txin); // FCMP++ carries no ring members: key_offsets stay empty

  for (int i = 0; i < 2; ++i)
  {
    tx_out txout{};
    txout.amount = 0;
    txout_to_tagged_key tagged{};
    memset(&tagged.key, i == 0 ? 0x01 : 0x03, sizeof(tagged.key));
    tagged.view_tag.data = static_cast<uint8_t>(i);
    txout.target = tagged;
    tx.vout.push_back(txout);
  }

  ct::CtSig &rv = tx.ct_signatures;
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  memset(&rv.referenceBlock, 0, sizeof(rv.referenceBlock));
  rv.outPk.resize(2);
  for (auto &pk : rv.outPk)
  {
    memset(pk.mask.bytes, 0x66, sizeof(pk.mask.bytes));
    pk.mask.bytes[0] = 0x58; // compressed Ed25519 basepoint
  }
  rv.enc_amounts.resize(2);
  rv.enc_amounts[0].fill(0);
  rv.enc_amounts[1].fill(0);
  rv.enc_labels.resize(2);
  rv.enc_labels[0].fill(0);
  rv.enc_labels[1].fill(0);

  ct::BulletproofPlus bpp{};
  bpp.L.resize(7); // capacity 2 amounts, matching the two outputs
  bpp.R.resize(7);
  rv.p.bulletproofs_plus.push_back(bpp);
  rv.p.curve_trees_tree_depth = 1;
  rv.p.fcmp_pp_proof.assign(8, 0);
  rv.p.pseudoOuts.resize(1);

  pqc_authentication auth{};
  auth.auth_version = 1;
  auth.scheme_id = 1;
  auth.flags = 0;
  auth.hybrid_public_key.assign(config::PQC_HYBRID_SINGLE_KEY_LEN, 0);
  auth.hybrid_signature.assign(config::PQC_HYBRID_SINGLE_SIG_LEN, 0);
  tx.pqc_auths.push_back(auth);

  return tx;
}

} // namespace

TEST(pruned_tx_hash_parity, pruned_spend_identity_matches_the_rust_oracle)
{
  const PrunedHashKat k = load_kat();

  // The same transaction serializes to the pinned bytes.
  transaction tx = build_kat_tx();
  blobdata blob;
  ASSERT_TRUE(t_serializable_object_to_blob(tx, blob));
  EXPECT_EQ(epee::string_tools::buff_to_hex_nodelimer(blob), k.tx_hex)
      << "C++ and shekyl-wire disagree on the spend's bytes";

  // The pinned bytes parse back through the production entry point.
  transaction parsed;
  blobdata pinned_blob;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(k.tx_hex, pinned_blob));
  ASSERT_TRUE(parse_and_validate_tx_from_blob(pinned_blob, parsed))
      << "the Rust-authored bytes must be a transaction C++ can parse";

  // The txid, from the full body.
  EXPECT_EQ(epee::string_tools::pod_to_hex(get_transaction_hash(parsed)), k.tx_hash_hex)
      << "tx id differs across languages";

  // The prunable digest, from the production derivation.
  crypto::hash prunable_hash;
  const blobdata_ref blob_ref(pinned_blob);
  ASSERT_TRUE(calculate_transaction_prunable_hash(parsed, &blob_ref, prunable_hash));
  EXPECT_EQ(epee::string_tools::pod_to_hex(prunable_hash), k.prunable_hash_hex)
      << "prunable digest differs across languages";

  // The bound surface: the pruned identity with the digest supplied is the
  // txid -- the recomputation the Rust engine performs against an untrusted
  // daemon's pruned reply, and the derivation `prune_tx_data` preserves the
  // operands of (txs_prunable_hash / txs_pqc_auths, LMDB schema v11).
  EXPECT_EQ(epee::string_tools::pod_to_hex(get_pruned_transaction_hash(parsed, prunable_hash)),
            k.tx_hash_hex)
      << "pruned identity (supplied digest) diverged from the txid";

  // The pruned framing the daemon serves: `serialize_base` equals the pin
  // and is a prefix of the full blob -- the split identity
  // `get_pruned_tx_blob` reassembles from `txs_pruned` + `txs_pqc_auths`.
  std::stringstream ss;
  binary_archive<true> ba(ss);
  ASSERT_TRUE(parsed.serialize_base(ba));
  const std::string pruned_bytes = ss.str();
  EXPECT_EQ(epee::string_tools::buff_to_hex_nodelimer(pruned_bytes), k.pruned_hex)
      << "pruned (serialize_base) framing differs across languages";
  ASSERT_LE(pruned_bytes.size(), blob.size());
  EXPECT_EQ(pruned_bytes, blob.substr(0, pruned_bytes.size()))
      << "the pruned form must be a prefix of the full form";

  // And the production pruned parser accepts the pruned bytes and still
  // derives the same identity.
  transaction pruned_parsed;
  blobdata pruned_pin;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(k.pruned_hex, pruned_pin));
  ASSERT_TRUE(parse_and_validate_tx_base_from_blob(blobdata_ref(pruned_pin), pruned_parsed))
      << "the served pruned framing must parse through the production pruned entry";
  EXPECT_EQ(epee::string_tools::pod_to_hex(get_pruned_transaction_hash(pruned_parsed, prunable_hash)),
            k.tx_hash_hex)
      << "pruned identity from the pruned body diverged from the txid";
}
