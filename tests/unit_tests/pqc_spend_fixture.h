// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// A minimal but well-formed v3 FCMP++/PQC spend, single-sourced so the LMDB
// depth-pass tests (tx_data_pruning_lmdb.cpp) and the RPC facts-shim tests
// (rpc_facts_shims.cpp) exercise the exact same transaction shape and cannot
// drift. A v1 stand-in does not survive `get_transaction_prunable_hash`,
// and Shekyl is v3-from-genesis, so v3 is the only honest pool inhabitant.

#pragma once

#include <cstring>

#include "cryptonote_basic/cryptonote_basic.h"

namespace shekyl_test_fixtures
{

inline cryptonote::transaction make_pqc_spend()
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;

  cryptonote::txin_to_key txin{};
  txin.amount = 0;
  std::memset(&txin.k_image, 0xBB, sizeof(txin.k_image));
  tx.vin.push_back(txin); // FCMP++ carries no ring members, so key_offsets stay empty

  cryptonote::tx_out txout{};
  txout.amount = 0;
  cryptonote::txout_to_tagged_key tagged{};
  // A canonical, prime-order, non-identity point — the Ed25519 basepoint's
  // compressed encoding. Consensus admission (check_outs_valid ->
  // shekyl_check_output_keys) accepts nothing weaker, and the curve-tree leaf
  // collector now ABORTS on an output it cannot encode (CEN-L11) instead of
  // silently skipping it. Arbitrary bytes here used to leave this tx's output
  // out of the tree with no signal, so the fixture only appeared to exercise
  // the block path.
  std::memset(&tagged.key, 0x66, sizeof(tagged.key));
  tagged.key.data[0] = 0x58;
  tagged.view_tag.data = 0;
  txout.target = tagged;
  tx.vout.push_back(txout);

  ct::CtSig& rv = tx.ct_signatures;
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  std::memset(&rv.referenceBlock, 0xAD, sizeof(rv.referenceBlock));
  rv.outPk.resize(1);
  // A decodable curve point: the Ed25519 basepoint's compressed encoding.
  std::memset(rv.outPk[0].mask.bytes, 0x66, sizeof(rv.outPk[0].mask.bytes));
  rv.outPk[0].mask.bytes[0] = 0x58;
  rv.enc_amounts.resize(1);
  rv.enc_amounts[0].fill(0x42);
  rv.enc_labels.resize(1);
  rv.enc_labels[0].fill(0x43);

  ct::BulletproofPlus bpp{};
  bpp.L.resize(6);
  bpp.R.resize(6);
  rv.p.bulletproofs_plus.push_back(bpp);
  rv.p.curve_trees_tree_depth = 20;
  rv.p.fcmp_pp_proof = {0x01, 0x02, 0x03, 0x04, 0x05};
  rv.p.pseudoOuts.resize(1);

  cryptonote::pqc_authentication auth{};
  auth.auth_version = 1;
  auth.scheme_id = 0;
  auth.flags = 0;
  auth.hybrid_public_key.assign(64, 0x71);
  auth.hybrid_signature.assign(96, 0x72);
  tx.pqc_auths.push_back(auth);

  return tx;
}

}  // namespace shekyl_test_fixtures
