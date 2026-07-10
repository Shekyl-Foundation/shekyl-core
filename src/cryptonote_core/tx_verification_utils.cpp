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

#include <limits>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_verification_utils.h"
#include "hardforks/hardforks.h"
#include "fcmp/rctSigs.h"
#include "shekyl/shekyl_ffi.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "blockchain"

#define VER_ASSERT(cond, msgexpr) CHECK_AND_ASSERT_MES(cond, false, msgexpr)

using namespace cryptonote;

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

        // Serve-credit txs are non-spending: they carry no RCT output material
        // and verify BP+/balance on a dedicated fee-only path (the hybrid
        // signature lives on the vin), so they are excluded from the RCT
        // semantics batch (which would reject their empty fcmp_pp_proof).
        // Bond-post txs are handled by their own semantics check below.
        if (tx.version >= 2)
        {
            // Shared archival-tx taxonomy (classify_archival_tx,
            // cryptonote_basic.h) — single-sourced with check_tx_inputs and
            // check_tx_outputs so all three agree on the tx kind.
            const archival_tx_classification archival_class = classify_archival_tx(tx.vin);
            const bool archival_serve_credit_only = (archival_class.kind == archival_tx_kind::serve_credit_only);
            const size_t archival_bond_post_index = archival_class.special_index;
            const size_t spend_input_count = archival_class.spend_input_count;
            const bool is_archival_bond_post_tx = (archival_class.kind == archival_tx_kind::bond_post);
            const bool is_archival_emission_tx = (archival_class.kind == archival_tx_kind::emission);
            if (archival_serve_credit_only)
            {
                const rct::rctSig& rv = tx.rct_signatures;
                // Non-spending vin: no chain outputs, no fee, no RCT output material (gate-2 §5).
                if (!tx.pqc_auths.empty()
                    || !tx.vout.empty()
                    || rv.txnFee != 0
                    || !rv.outPk.empty()
                    || !rv.p.bulletproofs_plus.empty()
                    || !rv.p.fcmp_pp_proof.empty()
                    || !rv.p.pseudoOuts.empty()
                    || rv.type != rct::RCTTypeFcmpPlusPlusPqc
                    || !rct::verRctSemanticsFeeOnly(rv))
                {
                    tvc.m_verifivation_failed = true;
                    tvc.m_invalid_input = true;
                    return false;
                }
            }
            else if (is_archival_bond_post_tx)
            {
                const txin_archival_bond_post& bond =
                    std::get<txin_archival_bond_post>(tx.vin[archival_bond_post_index]);
                const rct::rctSig& rv = tx.rct_signatures;
                if (tx.pqc_auths.size() != tx.vin.size()
                    || spend_input_count == 0
                    || rv.p.pseudoOuts.size() != spend_input_count
                    || rv.p.fcmp_pp_proof.empty()
                    || rv.type != rct::RCTTypeFcmpPlusPlusPqc
                    || !rct::verRctSemanticsBondPost(rv, bond.bond_credit, bond.bond_debit))
                {
                    tvc.m_verifivation_failed = true;
                    tvc.m_invalid_input = true;
                    return false;
                }
            }
            else if (is_archival_emission_tx)
            {
                // C-1 emission CT semantics (E3 gating round §9.5 item 4). The
                // reward vouts are loud: their plaintext sum is the mint
                // credit, entering the CT balance on the input side. The deep
                // check that this sum equals the Rust-arithmetic reward total
                // is check_tx_inputs' (the vout_reward_sum operand); here only
                // the balance-equation shape is enforced. Fee inputs optional
                // (Q11): with zero, the fee is paid out of the mint.
                const rct::rctSig& rv = tx.rct_signatures;
                // Amount arithmetic in Rust (rule 20): single-sourced checked
                // sum, the SAME primitive check_tx_inputs uses for its reward
                // operand — the two totals cannot drift.
                std::vector<uint64_t> vout_amounts;
                vout_amounts.reserve(tx.vout.size());
                for (const auto& o : tx.vout)
                    vout_amounts.push_back(o.amount);
                uint64_t total_reward = 0;
                const bool reward_overflow = shekyl_checked_sum_amounts(
                    vout_amounts.empty() ? nullptr : vout_amounts.data(),
                    vout_amounts.size(), &total_reward) != 0;
                if (reward_overflow
                    || total_reward == 0
                    || tx.pqc_auths.size() != tx.vin.size()
                    || rv.p.pseudoOuts.size() != spend_input_count
                    || rv.type != rct::RCTTypeFcmpPlusPlusPqc
                    || !rct::verCtSemanticsEmission(rv, total_reward, spend_input_count))
                {
                    tvc.m_verifivation_failed = true;
                    tvc.m_invalid_input = true;
                    return false;
                }
            }
            else
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
            if (!rct::is_canonical_bulletproof_plus_layout(rv.p.bulletproofs_plus))
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
