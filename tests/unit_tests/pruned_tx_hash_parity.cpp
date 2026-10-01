// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Cross-language KAT for the FCMP++/PQC spend's bytes and identity, against
// shekyl-wire's pin (`pruned_tx_hash_parity_v1.json` -- full bytes, pruned
// bytes, prunable digest, archival length, txid).
//
// What this leg is an independent oracle FOR changed with SHT-Q2. The txid
// mixes the transaction's archival length, and there is one mixer, in Rust:
// `calculate_transaction_hash` serializes, cuts the blob at the offsets the
// serializer recorded, and calls it. So C++ no longer derives the mix a
// second time, and this file no longer claims to. What C++ still owns, and
// what this leg pins against bytes Rust authored, is everything that decides
// WHICH bytes reach the mixer:
//
//   - the same transaction, built field-by-field, serializes to `tx_hex`;
//   - `get_transaction_hash` produces `tx_hash_hex` -- which holds only if
//     `prefix_size`, `pqc_auths_offset` and `unprunable_size` cut the blob
//     where shekyl-wire's own parse puts those four regions (the Rust pin
//     was authored from the parsed body, not from slices);
//   - `calculate_transaction_prunable_hash` produces `prunable_hash_hex`;
//   - `serialize_base` -- the framing `get_pruned_tx_blob` reassembles from
//     `txs_pruned` + `txs_pqc_auths` and the daemon serves as
//     `pruned_as_hex` -- produces `pruned_hex`, a prefix of `tx_hex`;
//   - the bytes after `pqc_auths_offset` number `archival_len`, the operand
//     Rust measures from the same two ranges.
//
// The mix itself is pinned on the Rust side, where a hand-spelled derivation
// stands beside the mixer (shekyl-wire/tests/pruned_tx_hash_parity.rs). The
// pruned identity -- a pruned body, its digest and its length supplied -- is
// Rust-only (`Transaction::hash_with_supplied_prunable`): C++ has no pruned
// txid function, because a pruned body has no length here to measure.
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

#include "pqc_spend_fixture.h"

#ifndef PRUNED_TX_HASH_PARITY_FIXTURE_PATH
#define PRUNED_TX_HASH_PARITY_FIXTURE_PATH \
  "rust/shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json"
#endif

// The live-oracle sibling: bytes a running shekyld accepted under consensus
// verify and then connected. Kept a separate fixture on purpose -- the pin
// above is hand-built, deterministic and reproducible from a checkout alone,
// while this one needs a built daemon and a live run. Neither subsumes the
// other; do not consolidate them.
#ifndef LIVE_ORACLE_SPEND_FIXTURE_PATH
#define LIVE_ORACLE_SPEND_FIXTURE_PATH \
  "rust/shekyl-wire/tests/fixtures/live_oracle_spend_v1.json"
#endif

using namespace cryptonote;

namespace {

struct PrunedHashKat {
  std::string tx_hex;
  std::string pruned_hex;
  std::string prunable_hash_hex;
  std::string tx_hash_hex;
  uint64_t archival_len;
};

// The live-oracle capture. Only the bytes and the txid are recorded; every
// other identity is derived below by the production code, which is the point
// -- a fixture that also carried the prunable digest could disagree with
// itself.
struct LiveOracleKat {
  std::string tx_hex;
  std::string tx_hash_hex;
  std::string daemon_version;
};

LiveOracleKat load_live_oracle_kat()
{
  std::ifstream ifs(LIVE_ORACLE_SPEND_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing live-oracle spend fixture at ") + LIVE_ORACLE_SPEND_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("tx_hex") || !doc.HasMember("tx_hash_hex"))
    throw std::runtime_error("invalid live-oracle spend fixture");
  LiveOracleKat k{};
  k.tx_hex = doc["tx_hex"].GetString();
  k.tx_hash_hex = doc["tx_hash_hex"].GetString();
  k.daemon_version = doc.HasMember("accepted_by_daemon_version")
                         ? doc["accepted_by_daemon_version"].GetString()
                         : "";
  return k;
}

PrunedHashKat load_kat()
{
  std::ifstream ifs(PRUNED_TX_HASH_PARITY_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing pruned-hash parity fixture at ") + PRUNED_TX_HASH_PARITY_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("tx_hex") || !doc.HasMember("archival_len"))
    throw std::runtime_error("invalid pruned-hash parity fixture");
  PrunedHashKat k{};
  k.tx_hex = doc["tx_hex"].GetString();
  k.pruned_hex = doc["pruned_hex"].GetString();
  k.prunable_hash_hex = doc["prunable_hash_hex"].GetString();
  k.tx_hash_hex = doc["tx_hash_hex"].GetString();
  k.archival_len = doc["archival_len"].GetUint64();
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

  // CEN-I19: the pinned transaction carries the per-output PQC fields
  // consensus requires — exactly one 0x06 of 1120*n and one 0x07 of 32*n, in
  // that order, with the same filler bytes shekyl-wire's test helper uses
  // (`conforming_pqc_extra`). This side and the Rust side each CONSTRUCT the
  // transaction and the pin asserts their bytes are identical, so both must
  // build the transaction the network would accept; before this rule the pin
  // fixed agreement on a shape no builder can produce.
  shekyl_test_fixtures::append_pqc_kem_field(tx, SHEKYL_HYBRID_KEM_CT_BYTES * tx.vout.size());
  shekyl_test_fixtures::append_pqc_leaf_field(tx, SHEKYL_PQC_LEAF_ENTRY_BYTES * tx.vout.size());
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

  // The txid, from the full body: the blob cut at the serializer's offsets
  // and mixed in Rust equals the id Rust derived from its own parse.
  EXPECT_EQ(epee::string_tools::pod_to_hex(get_transaction_hash(parsed)), k.tx_hash_hex)
      << "tx id differs across languages";

  // The two ranges whose bytes are the archival length are the ones after
  // `pqc_auths_offset`. Counted here from the offsets, not asked of Rust:
  // this is the check that the ranges handed over are the ranges measured.
  ASSERT_LE(parsed.pqc_auths_offset.load(), pinned_blob.size());
  EXPECT_EQ(pinned_blob.size() - parsed.pqc_auths_offset.load(), k.archival_len)
      << "the bytes after pqc_auths_offset are not the pinned archival length";

  // The prunable digest, from the production derivation.
  crypto::hash prunable_hash;
  const blobdata_ref blob_ref(pinned_blob);
  ASSERT_TRUE(calculate_transaction_prunable_hash(parsed, &blob_ref, prunable_hash));
  EXPECT_EQ(epee::string_tools::pod_to_hex(prunable_hash), k.prunable_hash_hex)
      << "prunable digest differs across languages";

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

  // And the production pruned parser accepts the pruned bytes. It yields no
  // identity: a pruned body is refused by the txid function, by design.
  transaction pruned_parsed;
  blobdata pruned_pin;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(k.pruned_hex, pruned_pin));
  ASSERT_TRUE(parse_and_validate_tx_base_from_blob(blobdata_ref(pruned_pin), pruned_parsed))
      << "the served pruned framing must parse through the production pruned entry";
  crypto::hash refused;
  EXPECT_FALSE(calculate_transaction_hash(pruned_parsed, refused, nullptr))
      << "a pruned body has no archival length to measure and must not be named";
}

// A transaction its own serializer refuses has no id.
//
// `calculate_transaction_hash` cuts the serialized blob at the offsets the
// serializer recorded, and those offsets are set BEFORE the prunable region
// is written. So a refusal that arrives inside the prunable region leaves a
// blob whose three offsets are in order and whose tail is a fragment: every
// range check passes, and a mixer handed that fragment would return an id for
// bytes that are not a transaction. The serializer's verdict is the only
// thing that says so, and it must be read.
//
// The shape here is one spend input with two pseudo-outs: the prunable
// serializer writes the range proof, the tree depth and the membership proof
// and only then compares the pseudo-out count to the inputs.
TEST(pruned_tx_hash_parity, a_transaction_the_serializer_refuses_has_no_txid)
{
  // Control: the unmodified transaction serializes and is named.
  transaction tx = build_kat_tx();
  crypto::hash named;
  ASSERT_TRUE(calculate_transaction_hash(tx, named, nullptr));

  tx.ct_signatures.p.pseudoOuts.resize(2);

  // The fixture is what it claims: refused, after prunable bytes were written,
  // with the offsets still in order.
  blobdata fragment;
  ASSERT_FALSE(tx_to_blob(tx, fragment)) << "the serializer must refuse this body";
  ASSERT_LE(tx.prefix_size.load(), tx.pqc_auths_offset.load());
  ASSERT_LE(tx.pqc_auths_offset.load(), tx.unprunable_size.load());
  ASSERT_LT(tx.unprunable_size.load(), fragment.size())
      << "the refusal must arrive after part of the prunable region was written";

  crypto::hash refused;
  EXPECT_FALSE(calculate_transaction_hash(tx, refused, nullptr))
      << "a body the serializer refused was given an id over its fragment";
}

// The cross-language half of the live-oracle pin.
//
// The Rust leg re-serializes these bytes and recomputes the txid, which
// catches serializer drift but only within one language. This leg is the
// second parser: C++ parses the same daemon-accepted bytes with the
// production entry point, re-serializes them byte-exactly, and cuts them at
// its own offsets for the mixer. Agreement here means the two implementations
// agree about the regions of a transaction the network actually took, rather
// than of one we authored.
//
// Note what this test does NOT do, unlike its sibling above: it never rebuilds
// the transaction field by field. A real FCMP++ spend carries a membership
// proof and PQC auths that C++ cannot construct, which is exactly why the
// captured-bytes direction is the only one available -- and why the synthetic
// pin, which can be rebuilt on both sides, remains worth keeping.
TEST(pruned_tx_hash_parity, live_oracle_spend_identity_matches_the_accepted_bytes)
{
  const LiveOracleKat k = load_live_oracle_kat();

  // Rule 47: assert the subject before asserting about it. A truncated or
  // empty capture must fail here rather than parse-and-compare its way green.
  ASSERT_GT(k.tx_hex.size(), 2048u)
      << "the captured spend is too small to be an FCMP++ spend -- the fixture "
         "is truncated or was written by a failed capture";
  ASSERT_FALSE(k.daemon_version.empty())
      << "the capture must name the daemon that accepted it";

  blobdata blob;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(k.tx_hex, blob));

  // The bytes a daemon accepted must parse through the production entry point.
  transaction parsed;
  ASSERT_TRUE(parse_and_validate_tx_from_blob(blob, parsed))
      << "C++ cannot parse a transaction its own daemon accepted";

  // The identity the daemon indexed it under, recomputed here.
  EXPECT_EQ(epee::string_tools::pod_to_hex(get_transaction_hash(parsed)), k.tx_hash_hex)
      << "txid recomputed in C++ differs from the one the daemon accepted";

  // Re-serialization is byte-exact: the parse kept everything the chain carried.
  blobdata reserialized;
  ASSERT_TRUE(t_serializable_object_to_blob(parsed, reserialized));
  EXPECT_EQ(epee::string_tools::buff_to_hex_nodelimer(reserialized), k.tx_hex)
      << "C++ re-serialization changed the accepted spend's bytes";

}
