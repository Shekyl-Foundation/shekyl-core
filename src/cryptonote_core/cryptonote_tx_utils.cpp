// Copyright (c) 2014-2022, The Monero Project
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
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

// Shekyl: this file is consensus-oracle / miner-tx construction
// (construct_miner_tx, construct_tx_* used by tests/core_tests and the
// daemon). The product spend path is the Rust builder
// (shekyl-tx-builder + shekyl-engine-core). Do not grow a second wallet
// spend path here. See docs/FOLLOWUPS.md "C++ transaction builder is
// test-only".

#include <unordered_set>
#include <random>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "common/apply_permutation.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "crypto/pow_randomx.h"
#include "tx_pqc_verify.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/miner.h"
#include "shekyl/economics.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "fcmp/ct_semantics.h"

using namespace crypto;

namespace cryptonote
{
  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, uint64_t fee, uint64_t frozen_segment_count, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce, size_t max_outs, uint8_t hard_fork_version, shekyl::tx_volume_window tx_volume, shekyl::supply_facts supply, uint64_t genesis_ng_height) {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

    // The extra is built once, at the end, by shekyl_coinbase_extra: the
    // codec lays out [0x01 pubkey, 0x02 nonce(8), 0x06 KEM, 0x07 leaf
    // entries] and judges it by the coinbase grammar before handing the bytes
    // back (TX_EXTRA_RUST_CUTOVER.md §3, TXE-Q2, TXE-Q6'). The nonce is a
    // fixed SHEKYL_COINBASE_NONCE_BYTES: a miner's shorter request is
    // zero-padded and a longer one refused here, not at connect.
    CHECK_AND_ASSERT_MES(extra_nonce.size() <= SHEKYL_COINBASE_NONCE_BYTES, false,
      "coinbase extra_nonce is " << extra_nonce.size() << " bytes; at most "
      << SHEKYL_COINBASE_NONCE_BYTES << " (the field is fixed at that width)");
    uint8_t nonce[SHEKYL_COINBASE_NONCE_BYTES] = {0};
    std::copy(extra_nonce.begin(), extra_nonce.end(), nonce);
    keypair txkey = keypair::generate(hw::get_device("default"));

    txin_gen in;
    in.height = height;

    uint64_t block_reward;
    if(!get_block_reward(median_weight, current_block_weight, already_generated_coins, block_reward, hard_fork_version, tx_volume))
    {
      LOG_PRINT_L0("Block is too big");
      return false;
    }

    // Component 4: split emission between miner and staker pool
    shekyl::EmissionSplit em_split = shekyl::compute_emission_split(block_reward, height, genesis_ng_height);
    block_reward = em_split.miner_emission;

#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    LOG_PRINT_L1("Creating block template: miner_emission " << block_reward <<
      ", staker_emission " << em_split.staker_emission << ", fee " << fee);
#endif
    // Component 2: adaptive fee burn. frozen_segment_count must be the same
    // parent-state n connect-time validation will judge this coinbase against
    // (create_block_template computes it once for both construction passes).
    shekyl::BurnResult burn = shekyl::compute_fee_burn(fee, tx_volume, supply, frozen_segment_count);
    block_reward += burn.miner_fee_income;

    // Single "dusty" output with identity-mask RCT (active from genesis on rebooted chain).
    std::vector<uint64_t> out_amounts;
    decompose_amount_into_digits(block_reward, 0,
      [&out_amounts](uint64_t a_chunk) { out_amounts.push_back(a_chunk); },
      [&out_amounts](uint64_t a_dust) { out_amounts.push_back(a_dust); });

    CHECK_AND_ASSERT_MES(1 <= max_outs, false, "max_out must be non-zero");
    while (max_outs < out_amounts.size())
    {
      out_amounts[1] += out_amounts[0];
      for (size_t n = 1; n < out_amounts.size(); ++n)
        out_amounts[n - 1] = out_amounts[n];
      out_amounts.pop_back();
    }

    uint64_t summary_amounts = 0;

    CHECK_AND_ASSERT_MES(hard_fork_version >= HF_VERSION_FCMP_PLUS_PLUS_PQC, false,
      "construct_miner_tx: hard_fork_version " << (int)hard_fork_version
      << " < HF_VERSION_FCMP_PLUS_PLUS_PQC. Shekyl is v3 from genesis.");
    CHECK_AND_ASSERT_MES(!miner_address.m_pqc_public_key.empty(), false,
      "Miner address has no PQC public key; v3 requires per-output KEM encapsulation. "
      "Regenerate your miner wallet with `--generate-new-wallet` on a v3 build.");
    {
      CHECK_AND_ASSERT_MES(miner_address.m_pqc_public_key.size() == SHEKYL_PQC_PUBLIC_KEY_BYTES,
        false, "miner PQC public key size " << miner_address.m_pqc_public_key.size()
        << " != expected " << SHEKYL_PQC_PUBLIC_KEY_BYTES
        << " (x25519[32] || ml_kem_ek[1184])");

      const uint8_t* pk_x25519 = miner_address.m_pqc_public_key.data();
      const uint8_t* pk_ml_kem = miner_address.m_pqc_public_key.data() + SHEKYL_X25519_PK_BYTES;
      const size_t pk_ml_kem_len = miner_address.m_pqc_public_key.size() - SHEKYL_X25519_PK_BYTES;

      std::vector<uint8_t> kem_blob;
      kem_blob.reserve(out_amounts.size() * SHEKYL_HYBRID_KEM_CT_BYTES);
      std::vector<uint8_t> leaf_blob;
      leaf_blob.reserve(out_amounts.size() * SHEKYL_PQC_LEAF_ENTRY_BYTES);

      tx.ct_signatures.outPk.resize(out_amounts.size());
      tx.ct_signatures.enc_amounts.resize(out_amounts.size());
      tx.ct_signatures.enc_labels.resize(out_amounts.size());

      for (size_t i = 0; i < out_amounts.size(); ++i)
      {
        ShekylOutputData od = shekyl_construct_output(
          reinterpret_cast<const uint8_t*>(&txkey.sec),
          pk_x25519, pk_ml_kem, pk_ml_kem_len,
          reinterpret_cast<const uint8_t*>(&miner_address.m_spend_public_key),
          out_amounts[i], static_cast<uint64_t>(i));
        CHECK_AND_ASSERT_MES(od.success, false,
          "shekyl_construct_output failed for coinbase output " << i);

        crypto::public_key out_key;
        memcpy(out_key.data, od.output_key, 32);
        crypto::view_tag vt;
        vt.data = od.view_tag_prefilter;

        tx_out out;
        cryptonote::set_tx_out(out_amounts[i], out_key, true, vt, out);
        tx.vout.push_back(out);

        memcpy(tx.ct_signatures.outPk[i].mask.bytes, od.commitment, 32);

        memcpy(tx.ct_signatures.enc_amounts[i].data(), od.enc_amount, 8);
        tx.ct_signatures.enc_amounts[i][8] = od.amount_tag;
        memcpy(tx.ct_signatures.enc_labels[i].data(), od.enc_label, 8);
        tx.ct_signatures.enc_labels[i][8] = od.label_tag;

        kem_blob.insert(kem_blob.end(), od.kem_ciphertext_x25519, od.kem_ciphertext_x25519 + 32);
        if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
          kem_blob.insert(kem_blob.end(), od.kem_ciphertext_ml_kem.ptr,
            od.kem_ciphertext_ml_kem.ptr + od.kem_ciphertext_ml_kem.len);

        leaf_blob.insert(leaf_blob.end(), od.pqc_leaf, od.pqc_leaf + SHEKYL_PQC_LEAF_ENTRY_BYTES);

        summary_amounts += out_amounts[i];
        ShekylOutputData tmp = od;
        shekyl_output_data_free(&tmp);
      }

      char msg[SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP] = {0};
      ShekylOwnedBuffer extra;
      const int32_t rc = shekyl_coinbase_extra(
        reinterpret_cast<const uint8_t*>(&txkey.pub), nonce,
        kem_blob.empty() ? nullptr : kem_blob.data(), kem_blob.size(),
        leaf_blob.empty() ? nullptr : leaf_blob.data(), leaf_blob.size(),
        out_amounts.size(), &extra.buf, msg, sizeof(msg));
      msg[sizeof(msg) - 1] = '\0';
      CHECK_AND_ASSERT_MES(rc == SHEKYL_TX_EXTRA_OK, false,
        "coinbase tx_extra refused at construction (code " << rc << "): " << msg);
      tx.extra.assign(extra.data(), extra.data() + extra.size());
    }

    tx.version = 3;

    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    tx.invalidate_hashes();

    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return true;
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(
      block& bl
    , std::string const & genesis_tx
    , uint32_t nonce
    )
  {
    //genesis block
    bl = {};

    blobdata tx_bl;
    bool r = string_tools::parse_hexstr_to_binbuff(genesis_tx, tx_bl);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = nonce;
    shekyl_curve_tree_selene_hash_init(reinterpret_cast<uint8_t*>(&bl.curve_tree_root));
    // attestation_root: block_header() already defaults to empty_attestation_root()
    // (Rust attestation_root(&[]) via FFI) — the valid empty-set commitment, not
    // null_hash (ARCHIVAL_CREDIT_WIRE.md §3). Genesis has no pass records.
    miner::find_nonce_for_given_block([](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, crypto::hash &hash){
      return cryptonote::get_block_longhash(NULL, b, hash, height, seed_hash);
    }, bl, 1, 0, NULL);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  bool get_altblock_longhash(const block& b, crypto::hash& res, const crypto::hash& seed_hash)
  {
    blobdata bd = get_block_hashing_blob(b);
    if (!hash_pow_randomx(bd.data(), bd.size(), seed_hash, res))
    {
      // The 0xff..ff sentinel is a BELT, not the gate: check_hash() rejects
      // it only at difficulty > 1 — at difficulty 1 every hash passes, so a
      // caller relying on the sentinel alone fails OPEN (CEN-D2). The
      // returned bool is the gate; the alt validation site rejects on it.
      memset(res.data, 0xff, sizeof(res.data));
      return false;
    }
    return true;
  }

  bool get_block_longhash(const Blockchain *pbc, const blobdata& bd, crypto::hash& res, const uint64_t height, const crypto::hash *seed_hash)
  {
    // nullptr means "look it up". The all-zero hash is a valid RandomX
    // genesis seed, so this cannot collapse to a non-null reference.
    const crypto::hash seed = seed_hash != nullptr
      ? *seed_hash
      : (pbc != nullptr
           ? pbc->get_pending_block_id_by_height(shekyl_pow_randomx_v2_seedheight(height))
           : crypto::null_hash);

    if (!hash_pow_randomx(bd.data(), bd.size(), seed, res))
    {
      // The 0xff..ff sentinel is a BELT, not the gate: it makes check_hash()
      // reject at any difficulty > 1, but at difficulty 1 every hash passes
      // ((2^256-1)*1 < 2^256), so the sentinel alone fails OPEN there
      // (CEN-D2). The returned bool is the gate — the block-validation call
      // sites and the longhash worker reject on it; the sentinel remains for
      // display-only callers that ignore the bool (RPC pow_hash fills).
      // Matches the fail-closed belt in get_altblock_longhash().
      memset(res.data, 0xff, sizeof(res.data));
      return false;
    }
    return true;
  }

  bool get_block_longhash(const Blockchain *pbc, const block& b, crypto::hash& res, const uint64_t height, const crypto::hash *seed_hash)
  {
    blobdata bd = get_block_hashing_blob(b);
    return get_block_longhash(pbc, bd, res, height, seed_hash);
  }

  crypto::hash get_block_longhash(const Blockchain *pbc, const block& b, const uint64_t height, const crypto::hash *seed_hash)
  {
    crypto::hash p = crypto::null_hash;
    get_block_longhash(pbc, b, p, height, seed_hash);
    return p;
  }
}
