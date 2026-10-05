// Copyright (c) 2025-2026, The Shekyl Foundation
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
#include "shekyl/shekyl_ffi.h"

#include <cstdint>
#include <vector>

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "blockchain"

namespace {
  constexpr uint8_t PQC_SCHEME_SINGLE = 1;
  constexpr uint8_t PQC_SCHEME_MULTISIG = 2;
  // Minimum multisig key container: version(1) + n_total(1) + m_required(1).
  // MSW-1: the single-key length and the DoS ceiling are the canonical
  // `config::PQC_HYBRID_SINGLE_KEY_LEN` / `config::PQC_MAX_PUBLIC_KEY_BLOB`
  // (the old local `HYBRID_SINGLE_KEY_LEN` shadow and the `2 + MAX*LEN` fossil
  // ceiling are deleted). Exact length + `n <= MAX` are enforced by the Rust
  // container parse (verify_multisig via shekyl_pqc_verify); this header const
  // is only the DoS lower bound.
  constexpr size_t MULTISIG_KEY_HEADER_LEN = 3;
}

namespace cryptonote
{

bool verify_transaction_pqc_auth(const transaction& tx)
{
  if (tx.version < 3 || tx.vin.empty() || std::holds_alternative<txin_gen>(tx.vin[0]))
    return true;
  if (tx.pqc_auths.size() != tx.vin.size() || tx.pqc_auths.empty())
  {
    MERROR("PQC verify: pqc_auths size " << tx.pqc_auths.size() << " does not match vin size " << tx.vin.size());
    return false;
  }

  // The signing preimage of every input, derived once by shekyl-wire from
  // the transaction's bytes (CEN-I17): 32 bytes per input, one per
  // authentication. The count is the arity just checked; a body whose
  // bytes disagree with it is refused here, never verified against a
  // truncated or padded set.
  std::vector<uint8_t> signed_hashes(32 * tx.vin.size());
  size_t signed_count = 0;
  {
    const blobdata blob = t_serializable_object_to_blob(tx);
    char msg[160] = {0};
    const int32_t rc = shekyl_tx_pqc_signing_payload_hashes(
        reinterpret_cast<const uint8_t*>(blob.data()), blob.size(),
        signed_hashes.data(), tx.vin.size(), &signed_count,
        msg, sizeof(msg));
    if (rc != SHEKYL_TX_SIGNING_OK)
    {
      MERROR("PQC verify: signing preimage refused (code " << rc << "): " << msg);
      return false;
    }
    if (signed_count != tx.pqc_auths.size())
    {
      MERROR("PQC verify: " << signed_count << " signing preimage(s) for " << tx.pqc_auths.size() << " pqc_auths");
      return false;
    }
  }

  for (size_t idx = 0; idx < tx.pqc_auths.size(); ++idx)
  {
    const pqc_authentication& auth = tx.pqc_auths[idx];

    if (auth.auth_version != 1)
    {
      MERROR("PQC verify: unsupported auth_version " << (int)auth.auth_version << " (expected 1, input " << idx << ")");
      return false;
    }

    if (auth.flags != 0)
    {
      MERROR("PQC verify: non-zero flags 0x" << std::hex << auth.flags << std::dec << " (input " << idx << ")");
      return false;
    }

    if (auth.scheme_id != PQC_SCHEME_SINGLE && auth.scheme_id != PQC_SCHEME_MULTISIG)
    {
      MERROR("PQC verify: unknown scheme_id " << (int)auth.scheme_id << " (input " << idx << ")");
      return false;
    }

    if (auth.hybrid_public_key.empty())
    {
      MERROR("PQC verify: empty hybrid_public_key (input " << idx << ")");
      return false;
    }

    if (auth.scheme_id == PQC_SCHEME_SINGLE)
    {
      if (auth.hybrid_public_key.size() != config::PQC_HYBRID_SINGLE_KEY_LEN)
      {
        MERROR("PQC verify: single-signer key blob size " << auth.hybrid_public_key.size()
               << " != expected " << config::PQC_HYBRID_SINGLE_KEY_LEN << " (input " << idx << ")");
        return false;
      }
    }
    else if (auth.scheme_id == PQC_SCHEME_MULTISIG)
    {
      if (auth.hybrid_public_key.size() < MULTISIG_KEY_HEADER_LEN)
      {
        MERROR("PQC verify: multisig key blob too short (" << auth.hybrid_public_key.size() << " bytes, input " << idx << ")");
        return false;
      }
      if (auth.hybrid_public_key.size() > config::PQC_MAX_PUBLIC_KEY_BLOB)
      {
        MERROR("PQC verify: multisig key blob exceeds maximum (" << auth.hybrid_public_key.size()
               << " > " << config::PQC_MAX_PUBLIC_KEY_BLOB << ", input " << idx << ")");
        return false;
      }
    }

    uint8_t pqc_result = shekyl_pqc_verify(
        auth.scheme_id,
        auth.hybrid_public_key.data(),
        auth.hybrid_public_key.size(),
        auth.hybrid_signature.data(),
        auth.hybrid_signature.size(),
        signed_hashes.data() + 32 * idx,
        32);

    if (pqc_result != 0)
    {
      MERROR("PQC verify failed: error code " << (int)pqc_result << " (input " << idx << ")");
      return false;
    }
  }

  return true;
}

} // namespace cryptonote
