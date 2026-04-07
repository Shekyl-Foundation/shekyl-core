// Copyright (c) 2023, The Monero Project
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

#include <boost/iterator/transform_iterator.hpp>

#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_verification_utils.h"
#include "hardforks/hardforks.h"
#include "fcmp/rctSigs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain"

#define VER_ASSERT(cond, msgexpr) CHECK_AND_ASSERT_MES(cond, false, msgexpr)

using namespace cryptonote;

static bool is_canonical_bulletproof_plus_layout(const std::vector<rct::BulletproofPlus> &proofs)
{
    if (proofs.size() != 1)
        return false;
    const size_t sz = proofs[0].V.size();
    if (sz == 0 || sz > BULLETPROOF_PLUS_MAX_OUTPUTS)
        return false;
    return true;
}

template <class TxForwardIt>
static bool ver_non_input_consensus_templated(TxForwardIt tx_begin, TxForwardIt tx_end,
        tx_verification_context& tvc, std::uint8_t hf_version)
{
    std::vector<const rct::rctSig*> rvv;
    rvv.reserve(static_cast<size_t>(std::distance(tx_begin, tx_end)));

    const size_t max_tx_version = hf_version < HF_VERSION_DYNAMIC_FEE ? 1 : (hf_version >= HF_VERSION_SHEKYL_NG ? 3 : 2);
    const size_t min_tx_version = hf_version >= HF_VERSION_SHEKYL_NG ? 3 : (hf_version >= HF_VERSION_DYNAMIC_FEE ? 2 : 1);

    const size_t tx_weight_limit = get_transaction_weight_limit(hf_version);

    for (; tx_begin != tx_end; ++tx_begin)
    {
        const transaction& tx = *tx_begin;
        const uint64_t blob_size = get_transaction_blob_size(tx);

        // Rule 1
        if (blob_size > get_max_tx_size())
        {
            tvc.m_verifivation_failed = true;
            tvc.m_too_big = true;
            return false;
        }

        // Rule 2 & 3
        if (tx.version < min_tx_version || tx.version > max_tx_version)
        {
            tvc.m_verifivation_failed = true;
            return false;
        }

        // Rule 4
        const size_t tx_weight = get_transaction_weight(tx, blob_size);
        if (hf_version >= HF_VERSION_PER_BYTE_FEE && tx_weight > tx_weight_limit)
        {
            tvc.m_verifivation_failed = true;
            tvc.m_too_big = true;
            return false;
        }

        // Rule 5
        if (!core::check_tx_semantic(tx, tvc, hf_version))
            return false;

        // Rule 6
        if (!Blockchain::check_tx_outputs(tx, tvc, hf_version) || tvc.m_verifivation_failed)
            return false;

        // Stake-claim transactions use RCTTypeFcmpPlusPlusPqc but have an empty
        // FCMP++ proof (ownership is proven via PQC auth on public amounts, not
        // membership proofs). Exclude them from the RCT semantics batch which
        // rejects empty fcmp_pp_proof.
        if (tx.version >= 2)
        {
            bool is_stake_claim_only = !tx.vin.empty();
            for (const auto& in : tx.vin)
            {
                if (!std::holds_alternative<txin_stake_claim>(in))
                { is_stake_claim_only = false; break; }
            }
            if (!is_stake_claim_only)
                rvv.push_back(&tx.rct_signatures);
        }
    }

    // Rule 7
    if (!ver_mixed_rct_semantics(std::move(rvv)))
    {
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_input = true;
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptonote
{

uint64_t get_transaction_weight_limit(const uint8_t hf_version)
{
    // from v8, limit a tx to 50% of the minimum block weight
    if (hf_version >= HF_VERSION_PER_BYTE_FEE)
        return get_min_block_weight(hf_version) / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    else
        return get_min_block_weight(hf_version) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}

bool ver_mixed_rct_semantics(std::vector<const rct::rctSig*> rvv)
{
    size_t batch_rv_size = 0; // this acts as an "end" iterator to the last simple batchable sig ptr
    for (size_t i = 0; i < rvv.size(); ++i)
    {
        const rct::rctSig& rv = *rvv[i];

        bool is_batchable_rv = false;

        switch (rv.type)
        {
        case rct::RCTTypeNull:
            MERROR("Unexpected Null rctSig type");
            return false;
            break;
        case rct::RCTTypeFcmpPlusPlusPqc:
            if (!is_canonical_bulletproof_plus_layout(rv.p.bulletproofs_plus))
            {
                MERROR("Bulletproof_plus does not have canonical form");
                return false;
            }
            is_batchable_rv = true;
            break;
        default:
            MERROR("Unknown rct type: " << rv.type);
            return false;
            break;
        }

        // Save this ring sig for later, as we will attempt simple RCT semantics batch verification
        if (is_batchable_rv)
            rvv[batch_rv_size++] = rvv[i];
    }

    if (batch_rv_size) // if any simple, batchable ring sigs...
    {
        rvv.resize(batch_rv_size);
        if (!rct::verRctSemanticsSimple(rvv))
        {
            MERROR("rct signature semantics check failed: simple-style batch verification failed");
            return false;
        }
    }

    return true;
}

bool ver_non_input_consensus(const transaction& tx, tx_verification_context& tvc,
    std::uint8_t hf_version)
{
    return ver_non_input_consensus_templated(&tx, &tx + 1, tvc, hf_version);
}

bool ver_non_input_consensus(const pool_supplement& ps, tx_verification_context& tvc,
    const std::uint8_t hf_version)
{
    // We already verified the pool supplement for this hard fork version! Yippee!
    if (ps.nic_verified_hf_version == hf_version)
        return true;

    const auto it_transform = [] (const decltype(ps.txs_by_txid)::value_type& in)
        -> const transaction& { return in.second.first; };
    const auto tx_begin = boost::make_transform_iterator(ps.txs_by_txid.cbegin(), it_transform);
    const auto tx_end = boost::make_transform_iterator(ps.txs_by_txid.cend(), it_transform);

    // Perform the checks...
    const bool verified = ver_non_input_consensus_templated(tx_begin, tx_end, tvc, hf_version);

    // Cache the hard fork version on success
    if (verified)
        ps.nic_verified_hf_version = hf_version;

    return verified;
}

} // namespace cryptonote
