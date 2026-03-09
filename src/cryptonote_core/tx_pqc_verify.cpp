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
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "shekyl/shekyl_ffi.h"
#include "serialization/binary_archive.h"

#include <sstream>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain"

namespace cryptonote
{

bool get_transaction_signed_payload(const transaction& tx, std::string& payload_out)
{
  if (tx.version < 3 || tx.vin.empty() || tx.vin[0].type() == typeid(txin_gen))
    return false;
  if (!tx.pqc_auth)
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

  std::string pqc_header_blob;
  {
    std::ostringstream ss;
    binary_archive<true> ba(ss);
    const pqc_authentication& auth = *tx.pqc_auth;
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

  payload_out = prefix_blob + rct_blob + pqc_header_blob;
  return true;
}

bool verify_transaction_pqc_auth(const transaction& tx)
{
  if (tx.version < 3 || tx.vin.empty() || tx.vin[0].type() == typeid(txin_gen))
    return true;  // not a v3 user tx, skip
  if (!tx.pqc_auth)
    return false;

  const pqc_authentication& auth = *tx.pqc_auth;

  // Build signed payload: cn_fast_hash(prefix || rct_signing_body || pqc_auth_header)
  std::string payload_blob;
  if (!get_transaction_signed_payload(tx, payload_blob))
    return false;

  crypto::hash payload_hash;
  cryptonote::get_blob_hash(payload_blob, payload_hash);

  // Call FFI verify
  bool ok = shekyl_pqc_verify(
      auth.hybrid_public_key.data(),
      auth.hybrid_public_key.size(),
      reinterpret_cast<const uint8_t*>(payload_hash.data),
      sizeof(payload_hash.data),
      auth.hybrid_signature.data(),
      auth.hybrid_signature.size());

  return ok;
}

} // namespace cryptonote
