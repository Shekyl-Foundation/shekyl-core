// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
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

#include "misc_log_ex.h"
#include "misc_language.h"
#include "common/perf_timer.h"
#include "common/threadpool.h"
#include "common/util.h"
#include "rctSigs.h"
#include "bulletproofs_plus.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

using namespace crypto;
using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "fcmp"

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace rct {
namespace
{
    BulletproofPlus make_dummy_bulletproof_plus(const std::vector<uint64_t> &outamounts, keyV &C, keyV &masks)
    {
        const size_t n_outs = outamounts.size();
        const key I = identity();
        size_t nrl = 0;
        while ((1u << nrl) < n_outs)
          ++nrl;
        nrl += 6;

        C.resize(n_outs);
        masks.resize(n_outs);
        for (size_t i = 0; i < n_outs; ++i)
        {
            masks[i] = I;
            key sv8, sv;
            sv = zero();
            sv.bytes[0] = outamounts[i] & 255;
            sv.bytes[1] = (outamounts[i] >> 8) & 255;
            sv.bytes[2] = (outamounts[i] >> 16) & 255;
            sv.bytes[3] = (outamounts[i] >> 24) & 255;
            sv.bytes[4] = (outamounts[i] >> 32) & 255;
            sv.bytes[5] = (outamounts[i] >> 40) & 255;
            sv.bytes[6] = (outamounts[i] >> 48) & 255;
            sv.bytes[7] = (outamounts[i] >> 56) & 255;
            sc_mul(sv8.bytes, sv.bytes, INV_EIGHT.bytes);
            addKeys2(C[i], INV_EIGHT, sv8, H);
        }

        return BulletproofPlus{keyV(n_outs, I), I, I, I, I, I, I, keyV(nrl, I), keyV(nrl, I)};
    }
}

    void fill_construct_tx_rct_stub(rctSig &rv, const key &message, xmr_amount txnFee,
        const crypto::hash &referenceBlock, const std::vector<xmr_amount> &inamounts,
        const std::vector<xmr_amount> &outamounts, const keyV &destinations, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(!inamounts.empty(), "fill_construct_tx_rct_stub: no inputs");
        const size_t n_out = outamounts.size();
        const size_t n_in = inamounts.size();
        CHECK_AND_ASSERT_THROW_MES(destinations.size() == n_out, "fill_construct_tx_rct_stub: destinations/outamounts mismatch");

        rv.type = RCTTypeFcmpPlusPlusPqc;
        rv.message = message;
        rv.txnFee = txnFee;
        rv.referenceBlock = referenceBlock;
        rv.p.curve_trees_tree_depth = 0;
        rv.p.fcmp_pp_proof.clear();

        rv.outPk.resize(n_out);
        rv.ecdhInfo.resize(n_out);
        for (size_t i = 0; i < n_out; ++i)
            rv.outPk[i].dest = copy(destinations[i]);

        keyV C, masks;
        rv.p.bulletproofs_plus.clear();
        rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(outamounts, C, masks));
        for (size_t i = 0; i < n_out; ++i)
            rv.outPk[i].mask = scalarmult8(C[i]);

        keyV amount_keys(n_out);
        for (size_t i = 0; i < n_out; ++i)
            amount_keys[i] = skGen();

        key sumout = zero();
        for (size_t i = 0; i < n_out; ++i)
        {
            sc_add(sumout.bytes, masks[i].bytes, sumout.bytes);
            rv.ecdhInfo[i].mask = copy(masks[i]);
            rv.ecdhInfo[i].amount = d2h(outamounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], true);
        }

        rv.p.pseudoOuts.resize(n_in);
        keyV a(n_in);
        key sumpouts = zero();
        for (size_t i = 0; i < n_in - 1; i++)
        {
            skGen(a[i]);
            sc_add(sumpouts.bytes, a[i].bytes, sumpouts.bytes);
            genC(rv.p.pseudoOuts[i], a[i], inamounts[i]);
        }
        const size_t last = n_in - 1;
        sc_sub(a[last].bytes, sumout.bytes, sumpouts.bytes);
        genC(rv.p.pseudoOuts[last], a[last], inamounts[last]);
    }

    BulletproofPlus proveRangeBulletproofPlus(keyV &C, keyV &masks, const std::vector<uint64_t> &amounts, epee::span<const key> sk, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
        masks.resize(amounts.size());
        for (size_t i = 0; i < masks.size(); ++i)
            masks[i] = hwdev.genCommitmentMask(sk[i]);
        BulletproofPlus proof = bulletproof_plus_PROVE(amounts, masks);
        CHECK_AND_ASSERT_THROW_MES(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproofPlus(const BulletproofPlus &proof)
    {
      try { return bulletproof_plus_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproofPlus(const std::vector<const BulletproofPlus*> &proofs)
    {
      try { return bulletproof_plus_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    key get_pre_mlsag_hash(const rctSig &rv, hw::device &hwdev)
    {
      keyV hashes;
      hashes.reserve(3);
      hashes.push_back(rv.message);
      crypto::hash h;

      std::stringstream ss;
      binary_archive<true> ba(ss);
      const size_t inputs = rv.p.pseudoOuts.size();
      const size_t outputs = rv.ecdhInfo.size();
      key prehash;
      CHECK_AND_ASSERT_THROW_MES(const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs),
          "Failed to serialize rctSigBase");
      cryptonote::get_blob_hash(ss.str(), h);
      hashes.push_back(hash2rct(h));

      keyV kv;
      CHECK_AND_ASSERT_THROW_MES(rv.type == RCTTypeFcmpPlusPlusPqc, "Unsupported RCT type in get_pre_mlsag_hash: " << rv.type);
      kv.reserve((6*2+6) * rv.p.bulletproofs_plus.size());
      for (const auto &p: rv.p.bulletproofs_plus)
      {
        kv.push_back(p.A);
        kv.push_back(p.A1);
        kv.push_back(p.B);
        kv.push_back(p.r1);
        kv.push_back(p.s1);
        kv.push_back(p.d1);
        for (size_t n = 0; n < p.L.size(); ++n)
          kv.push_back(p.L[n]);
        for (size_t n = 0; n < p.R.size(); ++n)
          kv.push_back(p.R[n]);
      }
      hashes.push_back(cn_fast_hash(kv));
      hwdev.mlsag_prehash(ss.str(), inputs, outputs, hashes, rv.outPk, prehash);
      return  prehash;
    }

    //ver FCMP++ simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctSemanticsSimple(const std::vector<const rctSig*> & rvv) {
      try
      {
        PERF_TIMER(verRctSemanticsSimple);

        std::vector<const BulletproofPlus*> bpp_proofs;

        for (const rctSig *rvp: rvv)
        {
          CHECK_AND_ASSERT_MES(rvp, false, "rctSig pointer is NULL");
          const rctSig &rv = *rvp;
          CHECK_AND_ASSERT_MES(rv.type == RCTTypeFcmpPlusPlusPqc,
              false, "verRctSemanticsSimple called on unsupported rctSig type");
          CHECK_AND_ASSERT_MES(!rv.p.fcmp_pp_proof.empty(),
              false, "FCMP++ proof is empty");
          CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus), false, "Mismatched sizes of outPk and bulletproofs_plus");
          CHECK_AND_ASSERT_MES(rv.pseudoOuts.empty(), false, "rv.pseudoOuts is not empty");
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");
        }

        for (const rctSig *rvp: rvv)
        {
          const rctSig &rv = *rvp;
          const keyV &pseudoOuts = rv.p.pseudoOuts;

          rct::keyV masks(rv.outPk.size());
          for (size_t i = 0; i < rv.outPk.size(); i++) {
            masks[i] = rv.outPk[i].mask;
          }
          key sumOutpks = addKeys(masks);
          DP(sumOutpks);
          const key txnFeeKey = scalarmultH(d2h(rv.txnFee));
          addKeys(sumOutpks, txnFeeKey, sumOutpks);

          key sumPseudoOuts = addKeys(pseudoOuts);
          DP(sumPseudoOuts);

          if (!equalKeys(sumPseudoOuts, sumOutpks)) {
            LOG_PRINT_L1("Sum check failed");
            return false;
          }

          for (size_t i = 0; i < rv.p.bulletproofs_plus.size(); i++)
            bpp_proofs.push_back(&rv.p.bulletproofs_plus[i]);
        }
        if (!bpp_proofs.empty() && !verBulletproofPlus(bpp_proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verified failed");
          return false;
        }

        return true;
      }
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    bool verRctSemanticsSimple(const rctSig & rv)
    {
      return verRctSemanticsSimple(std::vector<const rctSig*>(1, &rv));
    }

    //------------------------------------------------------------------------------------------------------------------------------
    // FCMP++ transaction construction: replaces ring signatures with a single
    // full-chain membership proof plus Bulletproofs+ range proofs.
    //------------------------------------------------------------------------------------------------------------------------------
    // Append a little-endian u32 to a byte vector.
    static void push_le_u32(std::vector<uint8_t> &buf, uint32_t val)
    {
        buf.push_back(static_cast<uint8_t>(val));
        buf.push_back(static_cast<uint8_t>(val >> 8));
        buf.push_back(static_cast<uint8_t>(val >> 16));
        buf.push_back(static_cast<uint8_t>(val >> 24));
    }

    rctSig genRctFcmpPlusPlus(
        const key &message,
        const ctkeyV &inSk,
        const ctkeyV &inPk,
        const keyV &destinations,
        const std::vector<xmr_amount> &inamounts,
        const std::vector<xmr_amount> &outamounts,
        const keyV &amount_keys,
        xmr_amount txnFee,
        const crypto::hash &referenceBlock,
        uint8_t tree_depth,
        const std::vector<std::vector<uint8_t>> &tree_paths,
        const std::vector<std::vector<fcmp_chunk_entry>> &leaf_chunk_entries,
        const std::vector<key> &pqc_pk_hashes,
        hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() > 0, "Empty inamounts");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inPk.size(), "Different number of inamounts/inPk");
        CHECK_AND_ASSERT_THROW_MES(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        CHECK_AND_ASSERT_THROW_MES(pqc_pk_hashes.size() == inamounts.size(), "Different number of pqc_pk_hashes/inputs");
        CHECK_AND_ASSERT_THROW_MES(tree_paths.size() == inamounts.size(), "Different number of tree_paths/inputs");
        CHECK_AND_ASSERT_THROW_MES(leaf_chunk_entries.size() == inamounts.size(), "Different number of leaf_chunk_entries/inputs");

        rctSig rv;
        rv.type = RCTTypeFcmpPlusPlusPqc;
        rv.message = message;
        rv.txnFee = txnFee;
        rv.referenceBlock = referenceBlock;
        rv.p.curve_trees_tree_depth = tree_depth;

        // --- Outputs: destinations + ECDH info ---
        rv.outPk.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());
        for (size_t i = 0; i < destinations.size(); i++)
            rv.outPk[i].dest = copy(destinations[i]);

        // --- Range proofs (Bulletproofs+) ---
        rv.p.bulletproofs_plus.clear();
        {
            keyV C, masks;
            if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
            {
                rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(outamounts, C, masks));
            }
            else
            {
                const epee::span<const key> keys{&amount_keys[0], amount_keys.size()};
                rv.p.bulletproofs_plus.push_back(proveRangeBulletproofPlus(C, masks, outamounts, keys, hwdev));
            }
            ctkeyV outSk(destinations.size());
            for (size_t i = 0; i < outamounts.size(); ++i)
            {
                rv.outPk[i].mask = rct::scalarmult8(C[i]);
                outSk[i].mask = masks[i];
            }

            // Encode ECDH info
            key sumout = zero();
            for (size_t i = 0; i < outSk.size(); ++i)
            {
                sc_add(sumout.bytes, outSk[i].mask.bytes, sumout.bytes);
                rv.ecdhInfo[i].mask = copy(outSk[i].mask);
                rv.ecdhInfo[i].amount = d2h(outamounts[i]);
                hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], true);
            }

            // --- Pseudo outputs (balance proof) ---
            rv.p.pseudoOuts.resize(inamounts.size());
            keyV a(inamounts.size());
            key sumpouts = zero();
            for (size_t i = 0; i < inamounts.size() - 1; i++)
            {
                skGen(a[i]);
                sc_add(sumpouts.bytes, a[i].bytes, sumpouts.bytes);
                genC(rv.p.pseudoOuts[i], a[i], inamounts[i]);
            }
            size_t last = inamounts.size() - 1;
            sc_sub(a[last].bytes, sumout.bytes, sumpouts.bytes);
            genC(rv.p.pseudoOuts[last], a[last], inamounts[last]);
        }

        // --- FCMP++ membership proof via Rust FFI ---
        const uint32_t num_inputs = static_cast<uint32_t>(inPk.size());

        // Serialize per-input witness into the variable-length wire format.
        std::vector<uint8_t> witness;
        const uint32_t SELENE_CHUNK_WIDTH = shekyl_curve_tree_selene_chunk_width();
        const uint32_t HELIOS_CHUNK_WIDTH = shekyl_curve_tree_helios_chunk_width();

        for (size_t i = 0; i < num_inputs; ++i)
        {
            // Fixed header: [O:32][I:32][C:32][h_pqc:32][x:32][y:32] = 192 bytes
            const size_t hdr_start = witness.size();
            witness.resize(hdr_start + 192);
            uint8_t* base = witness.data() + hdr_start;

            memcpy(base, inPk[i].dest.bytes, 32);       // O

            ge_p3 hp;
            hash_to_p3(hp, inPk[i].dest);
            key ki_gen;
            ge_p3_tobytes(reinterpret_cast<unsigned char*>(ki_gen.bytes), &hp);
            memcpy(base + 32, ki_gen.bytes, 32);         // I = Hp(O)

            memcpy(base + 64, inPk[i].mask.bytes, 32);   // C
            memcpy(base + 96, pqc_pk_hashes[i].bytes, 32); // h_pqc
            memcpy(base + 128, inSk[i].dest.bytes, 32);  // spend_key_x
            memcpy(base + 160, inSk[i].mask.bytes, 32);  // spend_key_y

            // Leaf chunk: Ed25519 output entries
            const auto& entries = leaf_chunk_entries[i];
            push_le_u32(witness, static_cast<uint32_t>(entries.size()));
            for (const auto& e : entries)
            {
                witness.insert(witness.end(), e.output_key.bytes, e.output_key.bytes + 32);
                witness.insert(witness.end(), e.key_image_gen.bytes, e.key_image_gen.bytes + 32);
                witness.insert(witness.end(), e.commitment.bytes, e.commitment.bytes + 32);
                witness.insert(witness.end(), e.h_pqc.bytes, e.h_pqc.bytes + 32);
            }

            // Parse daemon tree_path blob to extract branch layers.
            // Layer 0 (leaf scalars) is skipped here since we use Ed25519
            // points from leaf_chunk_entries instead. Branch layers start
            // after the layer-0 data in the blob.
            const auto& tp = tree_paths[i];

            // Skip layer 0: 2-byte position + chunk_count * 128 bytes
            size_t tp_off = 0;
            if (tp_off + 2 > tp.size())
            {
                LOG_PRINT_L0("Malformed tree path for input " << i << ": missing layer 0 position");
                push_le_u32(witness, 0); // c1_layer_count
                push_le_u32(witness, 0); // c2_layer_count
                continue;
            }
            tp_off += 2; // skip leaf_pos u16
            // Count leaf entries in layer 0
            const size_t leaf_entries_in_chunk = entries.size();
            tp_off += leaf_entries_in_chunk * 128; // skip leaf scalar data

            // Extract branch layers: alternating Selene (even) / Helios (odd)
            std::vector<std::vector<uint8_t>> c1_layers, c2_layers;
            for (uint8_t layer = 1; layer < tree_depth && tp_off + 2 <= tp.size(); ++layer)
            {
                tp_off += 2; // skip pos_in_parent u16
                uint32_t width = (layer % 2 == 0) ? SELENE_CHUNK_WIDTH : HELIOS_CHUNK_WIDTH;
                size_t layer_bytes = width * 32;
                if (tp_off + layer_bytes > tp.size())
                    layer_bytes = tp.size() - tp_off;

                std::vector<uint8_t> siblings(tp.begin() + tp_off, tp.begin() + tp_off + layer_bytes);
                tp_off += layer_bytes;

                // Layer 1 is Helios (odd), layer 2 is Selene (even), ...
                if (layer % 2 == 0)
                    c1_layers.push_back(std::move(siblings));
                else
                    c2_layers.push_back(std::move(siblings));
            }

            // Serialize C1 (Selene) branch layers
            push_le_u32(witness, static_cast<uint32_t>(c1_layers.size()));
            for (const auto& layer : c1_layers)
            {
                uint32_t sib_count = static_cast<uint32_t>(layer.size() / 32);
                push_le_u32(witness, sib_count);
                witness.insert(witness.end(), layer.begin(), layer.end());
            }

            // Serialize C2 (Helios) branch layers
            push_le_u32(witness, static_cast<uint32_t>(c2_layers.size()));
            for (const auto& layer : c2_layers)
            {
                uint32_t sib_count = static_cast<uint32_t>(layer.size() / 32);
                push_le_u32(witness, sib_count);
                witness.insert(witness.end(), layer.begin(), layer.end());
            }
        }

        // Tree root from the reference block.
        key tree_root;
        memcpy(tree_root.bytes, referenceBlock.data, 32);

        ShekylFcmpProveResult result = shekyl_fcmp_prove(
            witness.data(),
            witness.size(),
            num_inputs,
            tree_root.bytes,
            tree_depth,
            message.bytes);

        if (result.success && result.proof.ptr != nullptr && result.proof.len > 0)
        {
            rv.p.fcmp_pp_proof.assign(result.proof.ptr, result.proof.ptr + result.proof.len);
            shekyl_buffer_free(result.proof.ptr, result.proof.len);

            if (result.pseudo_outs.ptr != nullptr && result.pseudo_outs.len == num_inputs * 32)
            {
                rv.p.pseudoOuts.resize(num_inputs);
                for (size_t i = 0; i < num_inputs; ++i)
                    memcpy(rv.p.pseudoOuts[i].bytes, result.pseudo_outs.ptr + i * 32, 32);
                shekyl_buffer_free(result.pseudo_outs.ptr, result.pseudo_outs.len);
            }
        }
        else
        {
            LOG_PRINT_L0("shekyl_fcmp_prove failed for " << num_inputs << " inputs, depth " << (int)tree_depth);
        }

        return rv;
    }

    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, key &mask, hw::device &hwdev) {
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeFcmpPlusPlusPqc,
            false, "decodeRctSimple called on unsupported rctSig type");
        CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
        CHECK_AND_ASSERT_THROW_MES(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

        ecdhTuple ecdh_info = rv.ecdhInfo[i];
        hwdev.ecdhDecode(ecdh_info, sk, true);
        mask = ecdh_info.mask;
        key amount = ecdh_info.amount;
        key C = rv.outPk[i].mask;
        DP("C");
        DP(C);
        key Ctmp;
        CHECK_AND_ASSERT_THROW_MES(sc_check(mask.bytes) == 0, "warning, bad ECDH mask");
        CHECK_AND_ASSERT_THROW_MES(sc_check(amount.bytes) == 0, "warning, bad ECDH amount");
        addKeys2(Ctmp, mask, amount, H);
        DP("Ctmp");
        DP(Ctmp);
        if (equalKeys(C, Ctmp) == false) {
            CHECK_AND_ASSERT_THROW_MES(false, "warning, amount decoded incorrectly, will be unable to spend");
        }
        return h2d(amount);
    }

    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, hw::device &hwdev) {
      key mask;
      return decodeRctSimple(rv, sk, i, mask, hwdev);
    }
}
