// Copyright (c) 2024, The Monero Project
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
// PQC verification for TransactionV3 hybrid signatures.

#include "cryptonote_core/tx_pqc_verify.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_config.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "shekyl/shekyl_ffi.h"
#include "serialization/binary_archive.h"

#include <sstream>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain"

namespace {
  constexpr uint8_t PQC_SCHEME_SINGLE = 1;
  constexpr uint8_t PQC_SCHEME_MULTISIG = 2;
  constexpr size_t HYBRID_SINGLE_KEY_LEN = 1996; // Ed25519 (32) + ML-DSA-65 (1952) + 12 header
  constexpr size_t MULTISIG_KEY_HEADER_LEN = 2;  // n_total + m_required
  constexpr size_t MULTISIG_MAX_KEY_BLOB = MULTISIG_KEY_HEADER_LEN +
      (config::MAX_MULTISIG_PARTICIPANTS * HYBRID_SINGLE_KEY_LEN);
}

namespace cryptonote
{

bool get_transaction_signed_payload(const transaction& tx, size_t input_index, std::string& payload_out)
{
  if (tx.version < 3 || tx.vin.empty() || std::holds_alternative<txin_gen>(tx.vin[0]))
    return false;
  if (input_index >= tx.pqc_auths.size() || input_index >= tx.vin.size())
    return false;

  std::string prefix_blob;
  {
    std::ostringstream ss;
    binary_archive<true> ba(ss);
    ::serialization::serialize(ba, const_cast<transaction_prefix&>(static_cast<const transaction_prefix&>(tx)));
    prefix_blob = ss.str();
  }

  std::string rct_blob;
  {
    std::ostringstream ss;
    binary_archive<true> ba(ss);
    transaction& tt = const_cast<transaction&>(tx);
    const size_t inputs = tx.vin.size();
    const size_t outputs = tx.vout.size();
    if (!tt.rct_signatures.serialize_rctsig_base(ba, inputs, outputs))
      return false;
    rct_blob = ss.str();
  }

  // Serialize the current input's PQC header (auth_version, scheme_id, flags, key)
  std::string pqc_header_blob;
  {
    std::ostringstream ss;
    binary_archive<true> ba(ss);
    const pqc_authentication& auth = tx.pqc_auths[input_index];
    if (!::do_serialize(ba, const_cast<uint8_t&>(auth.auth_version)))
      return false;
    if (!::do_serialize(ba, const_cast<uint8_t&>(auth.scheme_id)))
      return false;
    if (!::do_serialize(ba, const_cast<uint16_t&>(auth.flags)))
      return false;
    if (!::do_serialize(ba, const_cast<std::vector<uint8_t>&>(auth.hybrid_public_key)))
      return false;
    pqc_header_blob = ss.str();
  }

  // Bind ALL inputs' PQC public key hashes into the signed payload.
  // Without this, an attacker could substitute one input's PQC key without
  // invalidating other inputs' signatures.
  std::string all_pqc_key_hashes;
  {
    for (size_t i = 0; i < tx.pqc_auths.size(); ++i)
    {
      const auto& a = tx.pqc_auths[i];
      crypto::hash h;
      cryptonote::get_blob_hash(
        std::string(reinterpret_cast<const char*>(a.hybrid_public_key.data()),
                    a.hybrid_public_key.size()), h);
      all_pqc_key_hashes.append(reinterpret_cast<const char*>(h.data), sizeof(h.data));
    }
  }

  payload_out = prefix_blob + rct_blob + pqc_header_blob + all_pqc_key_hashes;
  return true;
}

bool verify_transaction_pqc_auth(const transaction& tx)
{
  return verify_transaction_pqc_auth(tx, boost::none);
}

bool verify_transaction_pqc_auth(const transaction& tx,
                                  const boost::optional<uint8_t>& expected_scheme_id)
{
  if (tx.version < 3 || tx.vin.empty() || std::holds_alternative<txin_gen>(tx.vin[0]))
    return true;
  if (tx.pqc_auths.size() != tx.vin.size() || tx.pqc_auths.empty())
  {
    MERROR("PQC verify: pqc_auths size " << tx.pqc_auths.size() << " does not match vin size " << tx.vin.size());
    return false;
  }

  for (size_t idx = 0; idx < tx.pqc_auths.size(); ++idx)
  {
    const pqc_authentication& auth = tx.pqc_auths[idx];

    if (auth.scheme_id != PQC_SCHEME_SINGLE && auth.scheme_id != PQC_SCHEME_MULTISIG)
    {
      MERROR("PQC verify: unknown scheme_id " << (int)auth.scheme_id << " (input " << idx << ")");
      return false;
    }

    if (expected_scheme_id && auth.scheme_id != *expected_scheme_id)
    {
      MERROR("PQC verify: scheme_id mismatch (spend=" << (int)auth.scheme_id
             << ", output committed=" << (int)*expected_scheme_id << ", input " << idx << ")");
      return false;
    }

    if (auth.scheme_id == PQC_SCHEME_MULTISIG)
    {
      if (auth.hybrid_public_key.size() < MULTISIG_KEY_HEADER_LEN)
      {
        MERROR("PQC verify: multisig key blob too short (" << auth.hybrid_public_key.size() << " bytes, input " << idx << ")");
        return false;
      }
      if (auth.hybrid_public_key.size() > MULTISIG_MAX_KEY_BLOB)
      {
        MERROR("PQC verify: multisig key blob exceeds maximum (" << auth.hybrid_public_key.size()
               << " > " << MULTISIG_MAX_KEY_BLOB << ", input " << idx << ")");
        return false;
      }
    }

    std::string payload_blob;
    if (!get_transaction_signed_payload(tx, idx, payload_blob))
      return false;

    crypto::hash payload_hash;
    cryptonote::get_blob_hash(payload_blob, payload_hash);

    bool ok = shekyl_pqc_verify(
        auth.scheme_id,
        auth.hybrid_public_key.data(),
        auth.hybrid_public_key.size(),
        auth.hybrid_signature.data(),
        auth.hybrid_signature.size(),
        reinterpret_cast<const uint8_t*>(payload_hash.data),
        sizeof(payload_hash.data));

    if (!ok)
    {
      uint8_t err = shekyl_pqc_verify_debug(
          auth.scheme_id,
          auth.hybrid_public_key.data(),
          auth.hybrid_public_key.size(),
          auth.hybrid_signature.data(),
          auth.hybrid_signature.size(),
          reinterpret_cast<const uint8_t*>(payload_hash.data),
          sizeof(payload_hash.data));
      MERROR("PQC verify failed: error code " << (int)err << " (input " << idx << ")");
      return false;
    }
  }

  return true;
}

} // namespace cryptonote
