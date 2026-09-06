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
#include <stdexcept>

#include <sstream>
#include <string>
#include <typeinfo>
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "serialization/binary_archive.h"

namespace shekyl_test_fixtures
{

// n*G as a compressed point: canonical, prime-order, non-identity for
// 1 <= n <= 255. Consensus admission accepts nothing weaker for output keys
// (check_outs_valid), and for commitment masks it additionally rejects the
// *trivial amount-leaking forms* — the identity and bare G — so a fixture
// mask must use n >= 2 to be a shape the pool would actually admit.
inline crypto::public_key basepoint_multiple(unsigned n)
{
  if (n == 0 || n > 255)
    throw std::runtime_error("basepoint_multiple: n must be in [1, 255]");
  crypto::secret_key sk{};
  sk.data[0] = static_cast<char>(static_cast<unsigned char>(n));
  crypto::public_key pk{};
  if (!crypto::secret_key_to_public_key(sk, pk))
    throw std::runtime_error("basepoint_multiple: secret_key_to_public_key failed");
  return pk;
}

inline std::string serialize_tx_extra_field(const cryptonote::tx_extra_field& f)
{
  std::ostringstream oss;
  binary_archive<true> oar(oss);
  cryptonote::tx_extra_field v = f;
  if (!::do_serialize(oar, v))
    throw std::runtime_error("serialize_tx_extra_field failed");
  return oss.str();
}

/// Append a 0x06 KEM-ciphertext field of `bytes` bytes (arbitrary payload).
inline void append_pqc_kem_field(cryptonote::transaction& tx, size_t bytes)
{
  cryptonote::tx_extra_pqc_kem_ciphertext f;
  f.blob.assign(bytes, '\x6a');
  const std::string b = serialize_tx_extra_field(f);
  tx.extra.insert(tx.extra.end(), b.begin(), b.end());
}

/// Append a 0x07 leaf-hash field of `bytes` bytes (arbitrary payload).
inline void append_pqc_leaf_field(cryptonote::transaction& tx, size_t bytes)
{
  cryptonote::tx_extra_pqc_leaf_hashes f;
  f.blob.assign(bytes, '\x7b');
  const std::string b = serialize_tx_extra_field(f);
  tx.extra.insert(tx.extra.end(), b.begin(), b.end());
}

/// The conforming shape for `tx.vout.size()` outputs: one field of each — and
/// NEITHER field when there are no outputs. A zero-output transaction that
/// carries an empty 0x06 and an empty 0x07 is not "conforming with zero
/// bytes"; CEN-I19 forbids the fields entirely there, so a helper that
/// appended them would quietly manufacture a fixture the rule rejects.
inline void append_pqc_fields(cryptonote::transaction& tx)
{
  const size_t n = tx.vout.size();
  if (n == 0)
    return;
  append_pqc_kem_field(tx, cryptonote::HYBRID_KEM_CT_BYTES * n);
  append_pqc_leaf_field(tx, cryptonote::PQC_LEAF_HASH_BYTES * n);
}

/// Strip both PQC fields (the pre-rule shape every red-first vector starts from).
inline void strip_pqc_fields(cryptonote::transaction& tx)
{
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_pqc_kem_ciphertext));
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_pqc_leaf_hashes));
}

inline cryptonote::transaction make_pqc_spend()
{
  cryptonote::transaction tx{};
  tx.version = 3;
  tx.unlock_time = 0;

  cryptonote::txin_to_key txin{};
  txin.amount = 0;
  // A prime-order, non-identity key image: core::check_tx_semantic's domain
  // check (check_tx_inputs_keyimages_domain) rejects anything else, and this
  // fixture now also drives the admission path (tx_extra_pqc_field_shape.cpp),
  // not only the DB below it. A byte pattern here made every admission-level
  // vector look "rejected" for the wrong reason.
  const crypto::public_key ki_pt = basepoint_multiple(7);
  std::memcpy(&txin.k_image, &ki_pt, sizeof(txin.k_image));
  tx.vin.push_back(txin); // FCMP++ carries no ring members, so key_offsets stay empty

  cryptonote::tx_out txout{};
  txout.amount = 0;
  cryptonote::txout_to_tagged_key tagged{};
  // A canonical, prime-order, non-identity point. Consensus admission
  // (check_outs_valid -> shekyl_check_output_keys) accepts nothing weaker, and
  // the curve-tree leaf collector now ABORTS on an output it cannot encode
  // (CEN-L11) instead of silently skipping it. Arbitrary bytes here used to
  // leave this tx's output out of the tree with no signal, so the fixture only
  // appeared to exercise the block path.
  tagged.key = basepoint_multiple(3);
  tagged.view_tag.data = 0;
  txout.target = tagged;
  tx.vout.push_back(txout);

  ct::CtSig& rv = tx.ct_signatures;
  rv.type = ct::CTTypeFcmpPlusPlusPqc;
  rv.txnFee = 1000000;
  std::memset(&rv.referenceBlock, 0xAD, sizeof(rv.referenceBlock));
  rv.outPk.resize(1);
  // NOT bare G: shekyl_check_commitment_masks rejects the identity and G as
  // trivial amount-leaking forms (mask=0 and mask=1) on top of the
  // canonical/prime-order gate, so a G mask would make this fixture a shape
  // the pool refuses — invisible today only because these tests call the DB
  // below admission. 5*G is a commitment the gates accept.
  const crypto::public_key mask_pt = basepoint_multiple(5);
  std::memcpy(rv.outPk[0].mask.bytes, &mask_pt, sizeof(rv.outPk[0].mask.bytes));
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

  // The per-output PQC fields every transaction with outputs must carry
  // (GENESIS_TX_WIRE_FORMAT.md §9.6a, CEN-I19): one 0x06 of 1120 bytes and
  // one 0x07 of 32 bytes per output. The shape rule looks at counts and
  // lengths only, so the payloads are arbitrary; without them the DB
  // collector aborts (it used to zero-fill h_pqc silently).
  append_pqc_fields(tx);

  return tx;
}

}  // namespace shekyl_test_fixtures
