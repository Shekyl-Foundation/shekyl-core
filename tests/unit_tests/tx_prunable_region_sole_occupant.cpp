// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The prunable region has exactly ONE occupant, and until this file nothing said so.
//
// `calculate_transaction_prunable_hash` (cryptonote_format_utils.cpp:1135) computes
// the prunable-region hash two ways:
//
//   blob path         get_blob_hash(blob + unprunable_size, blob.size() - unprunable_size)
//                     -- the whole tail, wholesale
//   re-serialize path rct_signatures.p.serialize_rctsig_prunable(...)
//                     -- only rct_signatures.p
//
// They agree ONLY because `ctsig_prunable` is the last thing written by
// transaction::BEGIN_SERIALIZE (cryptonote_basic.h:645-648, where the object closes
// immediately after it). That equivalence is POSITIONAL. It has no name in the code
// and, before this file, no test.
//
// Append anything after `ctsig_prunable` and the two paths silently diverge: a node
// that kept the blob hashes the new bytes, a node re-serializing from the parsed
// struct does not. The failure surfaces at cryptonote_format_utils.cpp:1166 as
// "tx hash cash integrity failure" -- a THROW, on some nodes and not others,
// depending on whether they kept the blob. A moving split point would at least be a
// visible consequence; this is not.
//
// # Why this test is C++ (rule 20 exception, flagged rather than silent)
//
// Rule 20 sends new code and bug fixes to Rust. This invariant is a property of the
// C++ serializer's ORDERING, so the test must live where the defect can be
// introduced: a Rust test in `shekyl-wire` would be blind to a future C++ append,
// which is precisely the event it exists to catch.
//
// # Why length, not only hash
//
// Asserting the two hashes match says "different" when it fails. Asserting the two
// LENGTHS match names the defect -- "the prunable region has a second occupant" --
// and sends the next reader at a layout change rather than at a serialization bug.
// Both are asserted; the length assertion is the diagnostic one.
//
// See docs/design/ARCHIVAL_PASS_RECORD_CARRIER.md §1 and §4.

#include "gtest/gtest.h"

#include <cstring>
#include <sstream>

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "serialization/binary_archive.h"

using namespace cryptonote;

namespace {

// The re-serialize path's own output, reproduced here so its LENGTH can be compared
// against the blob tail. `calculate_transaction_prunable_hash` hashes this and
// discards the bytes, so the size is not otherwise observable.
bool prunable_reserialized_size(const transaction &t, size_t &out)
{
  if (t.rct_signatures.type == rct::CTTypeNull)
    return false;
  transaction &tt = const_cast<transaction &>(t);
  std::stringstream ss;
  binary_archive<true> ba(ss);
  if (!tt.rct_signatures.p.serialize_rctsig_prunable(
          ba, t.rct_signatures.type, count_spend_inputs(t.vin), t.vout.size()))
    return false;
  out = ss.str().size();
  return true;
}

// The property, asserted against one transaction. Callers supply the fixtures; a
// single hand-built tx would pass vacuously the moment someone adds an optional
// field that fixture does not populate (rule 50 -- a seal is not coverage).
void expect_prunable_region_has_one_occupant(const transaction &t, const char *what)
{
  SCOPED_TRACE(what);

  blobdata blob;
  ASSERT_TRUE(t_serializable_object_to_blob(t, blob)) << "could not serialize fixture";

  const unsigned int unprunable_size = t.unprunable_size;
  ASSERT_GT(unprunable_size, 0u) << "unprunable_size was never stamped -- the fixture "
                                    "did not go through the binary archive";
  ASSERT_LE(static_cast<size_t>(unprunable_size), blob.size());

  if (t.rct_signatures.type == rct::CTTypeNull)
  {
    // No prunable region at all: the tail must be empty, or something is living
    // past `unprunable_size` that the CTTypeNull early-out at
    // cryptonote_format_utils.cpp:1274 would hash as null.
    EXPECT_EQ(blob.size(), static_cast<size_t>(unprunable_size))
        << "a CTTypeNull tx has bytes after unprunable_size; its prunable hash is "
           "hardcoded null, so those bytes are committed to by NOTHING";
    return;
  }

  size_t reserialized = 0;
  ASSERT_TRUE(prunable_reserialized_size(t, reserialized))
      << "serialize_rctsig_prunable failed on the fixture";
  const size_t tail = blob.size() - unprunable_size;

  // THE ASSERTION THIS FILE EXISTS FOR. If it fails, someone appended to the
  // transaction after `ctsig_prunable`, and the two paths of
  // calculate_transaction_prunable_hash no longer compute the same thing.
  EXPECT_EQ(tail, reserialized)
      << "the prunable region has a SECOND OCCUPANT.\n"
         "  blob tail after unprunable_size: " << tail << " bytes\n"
         "  rct_signatures.p re-serialized:  " << reserialized << " bytes\n"
         "Something is now written after ctsig_prunable in "
         "transaction::BEGIN_SERIALIZE (cryptonote_basic.h). The blob path of "
         "calculate_transaction_prunable_hash hashes it; the re-serialize path does "
         "not. Nodes that kept the blob will disagree with nodes that did not, and "
         "the disagreement surfaces as a 'tx hash cash integrity failure' throw at "
         "cryptonote_format_utils.cpp:1166.\n"
         "If the new bytes are meant to be prunable, put them INSIDE "
         "serialize_rctsig_prunable, where both paths see them by construction. "
         "See docs/design/ARCHIVAL_PASS_RECORD_CARRIER.md §1.";

  // The consequence, asserted directly: with the blob and without it, same hash.
  crypto::hash from_blob = crypto::null_hash;
  crypto::hash from_struct = crypto::null_hash;
  const blobdata_ref blobref(blob);
  ASSERT_TRUE(calculate_transaction_prunable_hash(t, &blobref, from_blob));
  ASSERT_TRUE(calculate_transaction_prunable_hash(t, nullptr, from_struct));
  EXPECT_EQ(from_blob, from_struct)
      << "blob-present and blob-absent prunable hashes disagree -- a pruned node and "
         "an archival node would compute different tx ids for the same transaction";
}

} // namespace

// A miner tx: CTTypeNull, so the assertion is that its tail is empty. This arm is
// the one that catches an append landing on the coinbase path, where the null
// early-out means nothing commits to the appended bytes at all.
TEST(tx_prunable_region, miner_tx_has_no_prunable_tail)
{
  account_base acc;
  acc.generate(crypto::secret_key{}, false, false, FAKECHAIN);
  transaction tx = AUTO_VAL_INIT(tx);
  const blobdata extra_nonce;
  ASSERT_TRUE(construct_miner_tx(0, 0, 10000000000000, 1000, /*fee=*/0,
                                 /*frozen_segment_count=*/0,
                                 acc.get_keys().m_account_address, tx, extra_nonce,
                                 /*max_outs=*/1));

  // Round-trip through the binary archive so `unprunable_size` is stamped: it is
  // only assigned inside the serializer (cryptonote_basic.h:635/707).
  blobdata blob;
  ASSERT_TRUE(t_serializable_object_to_blob(tx, blob));
  transaction parsed;
  ASSERT_TRUE(parse_and_validate_tx_from_blob(blob, parsed));

  expect_prunable_region_has_one_occupant(parsed, "construct_miner_tx");
}

// The arm the file exists for: a tx whose prunable region is NON-EMPTY, so the
// length equality is actually exercised.
//
// The miner arm above is `CTTypeNull` and therefore only reaches the empty-tail
// branch -- it would pass forever without the main assertion ever running. A
// second occupant appended after `ctsig_prunable` is only visible on a tx that
// HAS a prunable region, which makes this arm the coverage and the other one the
// boundary case.
//
// Structurally parseable, not cryptographically valid: it needs to survive
// `parse_and_validate_tx_from_blob` (serializer + `expand_transaction_1`) and
// nothing more. The one non-obvious constraint is the commitment mask, which
// `expand_transaction_1` multiplies by INV_EIGHT and which therefore throws on
// arbitrary bytes; the Ed25519 basepoint's compressed encoding is the cheapest
// valid point. Learned from `txpool_ref_age.cpp`'s `make_fcmp_shape_tx`, which
// cannot be reused directly -- it has internal linkage, and hoisting it into a
// shared header is a wider change than this round should carry.
TEST(tx_prunable_region, fcmp_tx_tail_matches_reserialized_prunable)
{
  transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;

  txin_to_key txin{};
  txin.amount = 0;
  memset(&txin.k_image, 0xBB, sizeof(txin.k_image));
  tx.vin.push_back(txin); // FCMP++ carries no ring members: key_offsets stay empty

  tx_out txout{};
  txout.amount = 0;
  txout_to_tagged_key tagged{};
  memset(&tagged.key, 0xCC, sizeof(tagged.key));
  tagged.view_tag.data = 0;
  txout.target = tagged;
  tx.vout.push_back(txout);

  rct::rctSig &rv = tx.rct_signatures;
  rv.type = rct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  memset(&rv.referenceBlock, 0xAD, sizeof(rv.referenceBlock));
  rv.outPk.resize(1);
  memset(rv.outPk[0].mask.bytes, 0x66, sizeof(rv.outPk[0].mask.bytes));
  rv.outPk[0].mask.bytes[0] = 0x58; // compressed Ed25519 basepoint
  rv.enc_amounts.resize(1);
  rv.enc_amounts[0].fill(0x42);
  rv.enc_labels.resize(1);
  rv.enc_labels[0].fill(0x43);

  rct::BulletproofPlus bpp{};
  bpp.L.resize(6); // L.size()==6 -> max_amounts 2^0 = 1 >= the single output
  bpp.R.resize(6);
  rv.p.bulletproofs_plus.push_back(bpp);
  rv.p.curve_trees_tree_depth = 20;
  rv.p.fcmp_pp_proof = {0x01, 0x02, 0x03, 0x04, 0x05};
  rv.p.pseudoOuts.resize(1);

  pqc_authentication auth{};
  auth.auth_version = 1;
  auth.scheme_id = 0;
  auth.flags = 0;
  tx.pqc_auths.push_back(auth);

  blobdata blob;
  ASSERT_TRUE(t_serializable_object_to_blob(tx, blob));
  transaction parsed;
  ASSERT_TRUE(parse_and_validate_tx_from_blob(blob, parsed));

  // Guard against the arm going vacuous: if the fixture ever stops producing a
  // prunable region, the equality below would hold trivially (0 == 0) and this
  // file would be back to testing only the boundary case.
  ASSERT_NE(parsed.rct_signatures.type, rct::CTTypeNull)
      << "fixture no longer has a prunable region -- the main assertion would pass "
         "vacuously";
  ASSERT_GT(blob.size(), static_cast<size_t>(parsed.unprunable_size))
      << "fixture produced an EMPTY prunable tail; the length equality would hold "
         "trivially and this arm would stop covering anything";

  expect_prunable_region_has_one_occupant(parsed, "FCMP++ shape tx");
}
