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

#include <unordered_set>
#include <random>
#include <iostream>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "common/apply_permutation.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "crypto/pow_registry.h"
#include "tx_pqc_verify.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_basic/tx_extra.h"
#include "shekyl/economics.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "fcmp/rctSigs.h"

using namespace crypto;

namespace cryptonote
{
  //---------------------------------------------------------------
  void classify_addresses(const std::vector<tx_destination_entry> &destinations, const std::optional<cryptonote::account_public_address>& change_addr, size_t &num_stdaddresses, size_t &num_subaddresses, account_public_address &single_dest_subaddress)
  {
    num_stdaddresses = 0;
    num_subaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (change_addr && dst_entr.addr == change_addr)
        continue;
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        if (dst_entr.is_subaddress)
        {
          ++num_subaddresses;
          single_dest_subaddress = dst_entr.addr;
        }
        else
        {
          ++num_stdaddresses;
        }
      }
    }
    LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses and " << num_subaddresses << " subaddresses");
  }
  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, uint64_t fee, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce, size_t max_outs, uint8_t hard_fork_version, uint64_t tx_volume_avg, uint64_t circulating_supply, uint64_t stake_ratio, uint64_t genesis_ng_height) {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

    keypair txkey = keypair::generate(hw::get_device("default"));
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if(!extra_nonce.empty())
      if(!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
        return false;
    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    txin_gen in;
    in.height = height;

    uint64_t block_reward;
    if(!get_block_reward(median_weight, current_block_weight, already_generated_coins, block_reward, hard_fork_version, tx_volume_avg))
    {
      LOG_PRINT_L0("Block is too big");
      return false;
    }

    // Component 4: split emission between miner and staker pool
    shekyl::EmissionSplit em_split = shekyl::compute_emission_split(block_reward, height, genesis_ng_height, hard_fork_version);
    block_reward = em_split.miner_emission;

#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    LOG_PRINT_L1("Creating block template: miner_emission " << block_reward <<
      ", staker_emission " << em_split.staker_emission << ", fee " << fee);
#endif
    // Component 2: adaptive fee burn
    shekyl::BurnResult burn = shekyl::compute_fee_burn(fee, tx_volume_avg, circulating_supply, stake_ratio, hard_fork_version);
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
      static constexpr size_t X25519_PK_BYTES = 32;
      CHECK_AND_ASSERT_MES(miner_address.m_pqc_public_key.size() > X25519_PK_BYTES,
        false, "miner PQC public key too short (need x25519[32] || ml_kem_ek[1184])");

      const uint8_t* pk_x25519 = miner_address.m_pqc_public_key.data();
      const uint8_t* pk_ml_kem = miner_address.m_pqc_public_key.data() + X25519_PK_BYTES;
      const size_t pk_ml_kem_len = miner_address.m_pqc_public_key.size() - X25519_PK_BYTES;

      tx_extra_pqc_kem_ciphertext kem_field;
      kem_field.blob.reserve(out_amounts.size() * HYBRID_KEM_CT_BYTES);
      tx_extra_pqc_leaf_hashes leaf_hash_field;
      leaf_hash_field.blob.reserve(out_amounts.size() * PQC_LEAF_HASH_BYTES);

      tx.rct_signatures.outPk.resize(out_amounts.size());
      tx.rct_signatures.enc_amounts.resize(out_amounts.size());

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
        vt.data = od.view_tag_x25519;

        tx_out out;
        cryptonote::set_tx_out(out_amounts[i], out_key, true, vt, out);
        tx.vout.push_back(out);

        memcpy(tx.rct_signatures.outPk[i].mask.bytes, od.commitment, 32);

        memcpy(tx.rct_signatures.enc_amounts[i].data(), od.enc_amount, 8);
        tx.rct_signatures.enc_amounts[i][8] = od.amount_tag;

        kem_field.blob.append(reinterpret_cast<const char*>(od.kem_ciphertext_x25519), 32);
        if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
          kem_field.blob.append(
            reinterpret_cast<const char*>(od.kem_ciphertext_ml_kem.ptr),
            od.kem_ciphertext_ml_kem.len);

        leaf_hash_field.blob.append(reinterpret_cast<const char*>(od.h_pqc), PQC_LEAF_HASH_BYTES);

        summary_amounts += out_amounts[i];
        ShekylOutputData tmp = od;
        shekyl_output_data_free(&tmp);
      }

      {
        std::ostringstream oss;
        binary_archive<true> oar(oss);
        tx_extra_field variant_field = kem_field;
        bool r = ::do_serialize(oar, variant_field);
        CHECK_AND_ASSERT_MES(r, false, "Failed to serialize KEM ciphertexts for coinbase tx_extra");
        std::string blob = oss.str();
        tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
      }
      {
        std::ostringstream oss;
        binary_archive<true> oar(oss);
        tx_extra_field variant_field = leaf_hash_field;
        bool r = ::do_serialize(oar, variant_field);
        CHECK_AND_ASSERT_MES(r, false, "Failed to serialize PQC leaf hashes for coinbase tx_extra");
        std::string blob = oss.str();
        tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
      }
      if (!sort_tx_extra(tx.extra, tx.extra))
        return false;
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
  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const std::optional<cryptonote::account_public_address>& change_addr)
  {
    account_public_address addr = {null_pkey, null_pkey};
    size_t count = 0;
    for (const auto &i : destinations)
    {
      if (i.amount == 0)
        continue;
      if (change_addr && i.addr == *change_addr)
        continue;
      if (i.addr == addr)
        continue;
      if (count > 0)
        return null_pkey;
      addr = i.addr;
      ++count;
    }
    if (count == 0 && change_addr)
      return change_addr->m_view_public_key;
    return addr.m_view_public_key;
  }
  //---------------------------------------------------------------
  bool construct_tx_with_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, bool rct, bool shuffle_outs, bool use_view_tags, uint8_t hf_version, rct::keyV *out_commitment_masks)
  {
    (void)additional_tx_keys; // v3 from genesis: KEM ciphertext replaces additional tx keys
    (void)use_view_tags;      // v3 always uses view tags via shekyl_construct_output
    hw::device &hwdev = sender_account_keys.get_device();

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    tx.set_null();

    tx.version = (rct && hf_version >= HF_VERSION_SHEKYL_NG) ? 3 : (rct ? 2 : 1);
    tx.unlock_time = 0;

    tx.extra = extra;
    crypto::public_key txkey_pub;

    // if we have a stealth payment id, find it and encrypt it with the tx key now
    std::vector<tx_extra_field> tx_extra_fields;
    if (parse_tx_extra(tx.extra, tx_extra_fields))
    {
      bool add_dummy_payment_id = true;
      tx_extra_nonce extra_nonce;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        crypto::hash payment_id = null_hash;
        crypto::hash8 payment_id8 = null_hash8;
        if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
        {
          LOG_PRINT_L2("Encrypting payment id " << payment_id8);
          crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
          if (view_key_pub == null_pkey)
          {
            LOG_ERROR("Destinations have to have exactly one output to support encrypted payment ids");
            return false;
          }

          if (!hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key))
          {
            LOG_ERROR("Failed to encrypt payment id");
            return false;
          }

          std::string extra_nonce;
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          remove_field_from_tx_extra(tx.extra, typeid(tx_extra_nonce));
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add encrypted payment id to tx extra");
            return false;
          }
          LOG_PRINT_L1("Encrypted payment ID: " << payment_id8);
          add_dummy_payment_id = false;
        }
        else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
          add_dummy_payment_id = false;
        }
      }

      // we don't add one if we've got more than the usual 1 destination plus change
      if (destinations.size() > 2)
        add_dummy_payment_id = false;

      if (add_dummy_payment_id)
      {
        // if we have neither long nor short payment id, add a dummy short one,
        // this should end up being the vast majority of txes as time goes on
        std::string extra_nonce;
        crypto::hash8 payment_id8 = null_hash8;
        crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
        if (view_key_pub == null_pkey)
        {
          LOG_ERROR("Failed to get key to encrypt dummy payment id with");
        }
        else
        {
          hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key);
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add dummy encrypted payment id to tx extra");
            // continue anyway
          }
        }
      }
    }
    else
    {
      MWARNING("Failed to parse tx extra");
      tx_extra_fields.clear();
    }

    struct input_generation_context_data
    {
      keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return false;
      }
      summary_inputs_money += src_entr.amount;

      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
      if (src_entr.v3_ho_valid)
      {
        // v3: x = ho + b, KI = x * Hp(O)
        crypto::secret_key x_secret;
        sc_add(reinterpret_cast<unsigned char*>(&x_secret),
               reinterpret_cast<const unsigned char*>(&src_entr.ho),
               reinterpret_cast<const unsigned char*>(&sender_account_keys.m_spend_secret_key));
        in_ephemeral.pub = out_key;
        in_ephemeral.sec = x_secret;
        crypto::generate_key_image(out_key, x_secret, img);
        memwipe(&x_secret, sizeof(x_secret));
      }
      else
      {
        if(!generate_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral, img, hwdev))
        {
          LOG_ERROR("Key image generation failed!");
          return false;
        }
        CHECK_AND_ASSERT_MES(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest,
          false, "derived public key mismatch with output public key at index " << idx);
      }

      //put key image into tx input
      txin_to_key input_to_key;
      input_to_key.amount = src_entr.amount;
      input_to_key.k_image = img;

      tx.vin.push_back(input_to_key);
    }

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = std::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = std::get<txin_to_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
    }
    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    add_tx_pub_key_to_extra(tx, txkey_pub);

    uint64_t summary_outs_money = 0;
    // Per-output data from construct_output (v3 only), used to overwrite stub RCT
    // and to provide HKDF-correct values to genRctFcmpPlusPlus.
    struct v3_output_rct {
      uint8_t commitment[32];
      std::array<uint8_t, 9> enc_amount_with_tag;
      uint8_t commitment_mask[32]; // HKDF z scalar
    };
    std::vector<v3_output_rct> v3_rct_data;

    if (hf_version >= HF_VERSION_FCMP_PLUS_PLUS_PQC)
    {
      // v3 unified loop: shekyl_construct_output produces O, C, KEM CT, PQC data.
      static constexpr size_t X25519_PK_BYTES = 32;
      tx_extra_pqc_kem_ciphertext kem_field;
      kem_field.blob.reserve(destinations.size() * HYBRID_KEM_CT_BYTES);
      tx_extra_pqc_leaf_hashes leaf_hash_field;
      leaf_hash_field.blob.reserve(destinations.size() * PQC_LEAF_HASH_BYTES);
      v3_rct_data.resize(destinations.size());

      size_t output_index = 0;
      for (const tx_destination_entry& dst_entr : destinations)
      {
        CHECK_AND_ASSERT_MES(dst_entr.amount > 0 || tx.version > 1, false,
          "Destination with wrong amount: " << dst_entr.amount);
        CHECK_AND_ASSERT_MES(dst_entr.addr.m_pqc_public_key.size() > X25519_PK_BYTES, false,
          "Destination " << output_index << " lacks PQC KEM public key");

        const uint8_t* pk_x25519 = dst_entr.addr.m_pqc_public_key.data();
        const uint8_t* pk_ml_kem = dst_entr.addr.m_pqc_public_key.data() + X25519_PK_BYTES;
        const size_t pk_ml_kem_len = dst_entr.addr.m_pqc_public_key.size() - X25519_PK_BYTES;

        ShekylOutputData od = shekyl_construct_output(
          reinterpret_cast<const uint8_t*>(&tx_key),
          pk_x25519, pk_ml_kem, pk_ml_kem_len,
          reinterpret_cast<const uint8_t*>(&dst_entr.addr.m_spend_public_key),
          dst_entr.amount, static_cast<uint64_t>(output_index));
        CHECK_AND_ASSERT_MES(od.success, false,
          "shekyl_construct_output failed for output " << output_index);

        crypto::public_key out_key;
        memcpy(out_key.data, od.output_key, 32);
        crypto::view_tag vt;
        vt.data = od.view_tag_x25519;

        tx_out out;
        if (dst_entr.is_staking)
          cryptonote::set_staked_tx_out(dst_entr.amount, out_key, vt, dst_entr.stake_tier, out);
        else
          cryptonote::set_tx_out(dst_entr.amount, out_key, true, vt, out);
        tx.vout.push_back(out);

        memcpy(v3_rct_data[output_index].commitment, od.commitment, 32);
        memcpy(v3_rct_data[output_index].enc_amount_with_tag.data(), od.enc_amount, 8);
        v3_rct_data[output_index].enc_amount_with_tag[8] = od.amount_tag;
        memcpy(v3_rct_data[output_index].commitment_mask, od.z, 32);

        kem_field.blob.append(reinterpret_cast<const char*>(od.kem_ciphertext_x25519), 32);
        if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
          kem_field.blob.append(
            reinterpret_cast<const char*>(od.kem_ciphertext_ml_kem.ptr),
            od.kem_ciphertext_ml_kem.len);

        leaf_hash_field.blob.append(reinterpret_cast<const char*>(od.h_pqc), PQC_LEAF_HASH_BYTES);

        summary_outs_money += dst_entr.amount;
        ShekylOutputData tmp = od;
        shekyl_output_data_free(&tmp);
        output_index++;
      }

      {
        std::ostringstream oss;
        binary_archive<true> oar(oss);
        tx_extra_field variant_field = kem_field;
        CHECK_AND_ASSERT_MES(::do_serialize(oar, variant_field), false,
          "Failed to serialize KEM ciphertexts for tx_extra");
        std::string blob = oss.str();
        tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
      }
      {
        std::ostringstream oss;
        binary_archive<true> oar(oss);
        tx_extra_field variant_field = leaf_hash_field;
        CHECK_AND_ASSERT_MES(::do_serialize(oar, variant_field), false,
          "Failed to serialize PQC leaf hashes for tx_extra");
        std::string blob = oss.str();
        tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
      }
    }
    else
    {
      // Shekyl is v3 from genesis — all transactions use HKDF output construction.
      LOG_ERROR("construct_tx_with_tx_key called with hf_version < HF_VERSION_FCMP_PLUS_PLUS_PQC. "
        "Shekyl has no pre-v3 transactions.");
      return false;
    }

    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    CHECK_AND_ASSERT_MES(tx.extra.size() <= MAX_TX_EXTRA_SIZE, false, "TX extra size (" << tx.extra.size() << ") is greater than max allowed (" << MAX_TX_EXTRA_SIZE << ")");

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
    }

    // check for watch only wallet
    bool zero_secret_key = true;
    for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
      zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
    if (zero_secret_key)
    {
      MDEBUG("Null secret key, skipping signatures");
    }

    if (tx.version == 1)
    {
      LOG_ERROR("v1 transactions are not supported on Shekyl");
      return false;
    }
    else
    {
      uint64_t amount_in = 0, amount_out = 0;
      rct::ctkeyV inSk;
      inSk.reserve(sources.size());
      rct::keyV destinations;
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<unsigned int> index;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        rct::ctkey ctkey;
        amount_in += sources[i].amount;
        inamounts.push_back(sources[i].amount);
        index.push_back(sources[i].real_output);
        ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
        ctkey.mask = sources[i].mask;
        inSk.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::ctkey));
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        crypto::public_key output_public_key;
        get_output_public_key(tx.vout[i], output_public_key);
        destinations.push_back(rct::pk2rct(output_public_key));
        outamounts.push_back(tx.vout[i].amount);
        amount_out += tx.vout[i].amount;
      }

      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct)
          std::get<txin_to_key>(tx.vin[i]).amount = 0;
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tx.vout[i].amount = 0;

      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash, hwdev);
      rct::ctkeyV outSk;
      // Serializable rctSig stub (dummy BP+); the wallet overwrites via genRctFcmpPlusPlus()
      // after constructing tree paths and per-output PQC material.
      rct::fill_construct_tx_rct_stub(tx.rct_signatures, rct::hash2rct(tx_prefix_hash), amount_in - amount_out,
          crypto::null_hash, inamounts, outamounts, destinations, hwdev);
      memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

      // v3: overwrite stub commitments and enc_amounts with real HKDF-derived values.
      // Export commitment masks (z scalars) so genRctFcmpPlusPlus can produce
      // BP+ proofs against the HKDF-derived commitments.
      if (!v3_rct_data.empty())
      {
        CHECK_AND_ASSERT_MES(v3_rct_data.size() == tx.rct_signatures.outPk.size(), false,
          "v3_rct_data size mismatch with outPk");
        for (size_t i = 0; i < v3_rct_data.size(); ++i)
        {
          memcpy(tx.rct_signatures.outPk[i].mask.bytes, v3_rct_data[i].commitment, 32);
          tx.rct_signatures.enc_amounts[i] = v3_rct_data[i].enc_amount_with_tag;
        }
        if (out_commitment_masks)
        {
          out_commitment_masks->resize(v3_rct_data.size());
          for (size_t i = 0; i < v3_rct_data.size(); ++i)
            memcpy((*out_commitment_masks)[i].bytes, v3_rct_data[i].commitment_mask, 32);
        }
        for (auto& rd : v3_rct_data)
          memwipe(rd.commitment_mask, 32);
      }

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size() || outSk.empty(), false, "outSk size does not match vout");
    }

    // PQC auth signing: for FCMP++ (HF1+), per-output derived keys are used.
    // The wallet handles PQC signing after genRctFcmpPlusPlus. Multisig
    // pre-assembled signatures are preserved as-is.
    if (tx.version >= 3)
    {
      const bool multisig_preassembled = !tx.pqc_auths.empty()
          && tx.pqc_auths[0].scheme_id == 2
          && !tx.pqc_auths[0].hybrid_signature.empty();

      if (multisig_preassembled)
      {
        MCINFO("construct_tx", "Pre-assembled multisig pqc_auths detected (scheme_id=2); skipping");
      }
      else
      {
        // Binary serialization requires |pqc_auths| == |vin| for v3 spends. The wallet
        // replaces these stubs with per-input ML-DSA-65 material after genRctFcmpPlusPlus().
        tx.pqc_auths.assign(tx.vin.size(), pqc_authentication{});
      }
    }

    MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, bool rct, bool use_view_tags, uint8_t hf_version, rct::keyV *out_commitment_masks)
  {
    hw::device &hwdev = sender_account_keys.get_device();
    hwdev.open_tx(tx_key);
    try {
      bool shuffle_outs = true;
      bool r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, tx_key, additional_tx_keys, rct, shuffle_outs, use_view_tags, hf_version, out_commitment_masks);
      hwdev.close_tx();
      return r;
    } catch(...) {
      hwdev.close_tx();
      throw;
    }
  }
  //---------------------------------------------------------------
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx)
  {
     std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
     subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0,0};
     crypto::secret_key tx_key;
     std::vector<crypto::secret_key> additional_tx_keys;
     std::vector<tx_destination_entry> destinations_copy = destinations;
     return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, tx_key, additional_tx_keys, false);
  }
  //---------------------------------------------------------------
  bool build_genesis_coinbase_from_destinations(
      const std::vector<tx_destination_entry>& destinations
    , std::string& tx_hex_out
    )
  {
    CHECK_AND_ASSERT_MES(!destinations.empty(), false,
        "build_genesis_coinbase_from_destinations: destinations list is empty");

    transaction tx{};
    tx.version = 3;
    tx.unlock_time = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

    txin_gen in;
    in.height = 0;
    tx.vin.push_back(in);

    keypair txkey = keypair::generate(hw::get_device("default"));
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    static constexpr size_t X25519_PK_BYTES = 32;
    tx_extra_pqc_kem_ciphertext kem_field;
    kem_field.blob.reserve(destinations.size() * HYBRID_KEM_CT_BYTES);
    tx_extra_pqc_leaf_hashes leaf_hash_field;
    leaf_hash_field.blob.reserve(destinations.size() * PQC_LEAF_HASH_BYTES);

    tx.rct_signatures.type = rct::RCTTypeNull;
    tx.rct_signatures.outPk.resize(destinations.size());
    tx.rct_signatures.enc_amounts.resize(destinations.size());

    uint64_t summary_amounts = 0;
    for (size_t i = 0; i < destinations.size(); ++i)
    {
      const auto& dest = destinations[i];
      CHECK_AND_ASSERT_MES(dest.addr.m_pqc_public_key.size() > X25519_PK_BYTES, false,
        "Genesis destination " << i << " lacks PQC KEM public key. "
        "All Shekyl addresses require PQC keys from genesis.");

      const uint8_t* pk_x25519 = dest.addr.m_pqc_public_key.data();
      const uint8_t* pk_ml_kem = dest.addr.m_pqc_public_key.data() + X25519_PK_BYTES;
      const size_t pk_ml_kem_len = dest.addr.m_pqc_public_key.size() - X25519_PK_BYTES;

      ShekylOutputData od = shekyl_construct_output(
        reinterpret_cast<const uint8_t*>(&txkey.sec),
        pk_x25519, pk_ml_kem, pk_ml_kem_len,
        reinterpret_cast<const uint8_t*>(&dest.addr.m_spend_public_key),
        dest.amount, static_cast<uint64_t>(i));
      CHECK_AND_ASSERT_MES(od.success, false,
        "shekyl_construct_output failed for genesis output " << i);

      crypto::public_key out_key;
      memcpy(out_key.data, od.output_key, 32);
      crypto::view_tag vt;
      vt.data = od.view_tag_x25519;

      tx_out out;
      cryptonote::set_tx_out(dest.amount, out_key, true, vt, out);
      tx.vout.push_back(out);

      memcpy(tx.rct_signatures.outPk[i].mask.bytes, od.commitment, 32);
      memcpy(tx.rct_signatures.enc_amounts[i].data(), od.enc_amount, 8);
      tx.rct_signatures.enc_amounts[i][8] = od.amount_tag;

      kem_field.blob.append(reinterpret_cast<const char*>(od.kem_ciphertext_x25519), 32);
      if (od.kem_ciphertext_ml_kem.ptr && od.kem_ciphertext_ml_kem.len > 0)
        kem_field.blob.append(
          reinterpret_cast<const char*>(od.kem_ciphertext_ml_kem.ptr),
          od.kem_ciphertext_ml_kem.len);

      leaf_hash_field.blob.append(reinterpret_cast<const char*>(od.h_pqc), PQC_LEAF_HASH_BYTES);

      summary_amounts += dest.amount;
      ShekylOutputData tmp = od;
      shekyl_output_data_free(&tmp);
    }

    {
      std::ostringstream oss;
      binary_archive<true> oar(oss);
      tx_extra_field variant_field = kem_field;
      bool r = ::do_serialize(oar, variant_field);
      CHECK_AND_ASSERT_MES(r, false, "Failed to serialize KEM ciphertexts for genesis tx_extra");
      std::string blob = oss.str();
      tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
    }
    {
      std::ostringstream oss;
      binary_archive<true> oar(oss);
      tx_extra_field variant_field = leaf_hash_field;
      bool r = ::do_serialize(oar, variant_field);
      CHECK_AND_ASSERT_MES(r, false, "Failed to serialize PQC leaf hashes for genesis tx_extra");
      std::string blob = oss.str();
      tx.extra.insert(tx.extra.end(), blob.begin(), blob.end());
    }
    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    tx.invalidate_hashes();

    blobdata blob;
    if (!tx_to_blob(tx, blob))
    {
      LOG_ERROR("genesis coinbase: tx_to_blob failed");
      std::cerr << "genesis coinbase: tx_to_blob failed (version=" << tx.version
                << ", vin=" << tx.vin.size()
                << ", vout=" << tx.vout.size()
                << ", rct_type=" << static_cast<unsigned>(tx.rct_signatures.type)
                << ")\n";
      return false;
    }

    tx_hex_out = string_tools::buff_to_hex_nodelimer(blob);
    LOG_PRINT_L1("genesis coinbase: " << destinations.size() << " outputs, total "
        << print_money(summary_amounts) << ", hex length " << tx_hex_out.size());
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
    miner::find_nonce_for_given_block([](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, unsigned int threads, crypto::hash &hash){
      return cryptonote::get_block_longhash(NULL, b, hash, height, seed_hash, threads);
    }, bl, 1, 0, NULL);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  void get_altblock_longhash(const block& b, crypto::hash& res, const crypto::hash& seed_hash)
  {
    blobdata bd = get_block_hashing_blob(b);
    rx_slow_hash(seed_hash.data, bd.data(), bd.size(), res.data);
  }

  bool get_block_longhash(const Blockchain *pbc, const blobdata& bd, crypto::hash& res, const uint64_t height, const int major_version, const crypto::hash *seed_hash, const int miners)
  {
    if (pbc != NULL && major_version >= RX_BLOCK_VERSION)
    {
      static const std::string longhash_202612 = "84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000";
      epee::string_tools::hex_to_pod(longhash_202612, res);
      return true;
    }
    const IPowSchema& pow_schema = get_pow_for_height(height, major_version);
    const crypto::hash* resolved_seed_hash = seed_hash;
    crypto::hash resolved_seed = crypto::null_hash;

    if (major_version >= RX_BLOCK_VERSION)
    {
      if (pbc != NULL)
      {
        const uint64_t seed_height = rx_seedheight(height);
        resolved_seed = seed_hash ? *seed_hash : pbc->get_pending_block_id_by_height(seed_height);
        resolved_seed_hash = &resolved_seed;
      }
      else
      {
        memset(&resolved_seed, 0, sizeof(resolved_seed));
        resolved_seed_hash = &resolved_seed;
      }
    }

    return pow_schema.hash(bd.data(), bd.size(), height, resolved_seed_hash, miners, res);
  }

  bool get_block_longhash(const Blockchain *pbc, const block& b, crypto::hash& res, const uint64_t height, const crypto::hash *seed_hash, const int miners)
  {
    blobdata bd = get_block_hashing_blob(b);
	return get_block_longhash(pbc, bd, res, height, b.major_version, seed_hash, miners);
  }

  crypto::hash get_block_longhash(const Blockchain *pbc, const block& b, const uint64_t height, const crypto::hash *seed_hash, const int miners)
  {
    crypto::hash p = crypto::null_hash;
    get_block_longhash(pbc, b, p, height, seed_hash, miners);
    return p;
  }
}
