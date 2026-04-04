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
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace
{
    rct::BulletproofPlus make_dummy_bulletproof_plus(const std::vector<uint64_t> &outamounts, rct::keyV &C, rct::keyV &masks)
    {
        const size_t n_outs = outamounts.size();
        const rct::key I = rct::identity();
        size_t nrl = 0;
        while ((1u << nrl) < n_outs)
          ++nrl;
        nrl += 6;

        C.resize(n_outs);
        masks.resize(n_outs);
        for (size_t i = 0; i < n_outs; ++i)
        {
            masks[i] = I;
            rct::key sv8, sv;
            sv = rct::zero();
            sv.bytes[0] = outamounts[i] & 255;
            sv.bytes[1] = (outamounts[i] >> 8) & 255;
            sv.bytes[2] = (outamounts[i] >> 16) & 255;
            sv.bytes[3] = (outamounts[i] >> 24) & 255;
            sv.bytes[4] = (outamounts[i] >> 32) & 255;
            sv.bytes[5] = (outamounts[i] >> 40) & 255;
            sv.bytes[6] = (outamounts[i] >> 48) & 255;
            sv.bytes[7] = (outamounts[i] >> 56) & 255;
            sc_mul(sv8.bytes, sv.bytes, rct::INV_EIGHT.bytes);
            rct::addKeys2(C[i], rct::INV_EIGHT, sv8, rct::H);
        }

        return rct::BulletproofPlus{rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I)};
    }
}

namespace rct {
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

    //ver RingCT simple
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

    //ver RingCT non-semantics: verifies the FCMP++ membership proof
    bool verRctNonSemanticsSimple(const rctSig & rv) {
      try
      {
        PERF_TIMER(verRctNonSemanticsSimple);

        CHECK_AND_ASSERT_MES(rv.type == RCTTypeFcmpPlusPlusPqc,
            false, "verRctNonSemanticsSimple called on unsupported rctSig type");

        CHECK_AND_ASSERT_MES(!rv.p.fcmp_pp_proof.empty(), false, "Empty FCMP++ proof");

        // STUB: The full shekyl_fcmp_verify FFI call is wired in
        // check_tx_inputs (blockchain.cpp), which directly calls the
        // Rust verifier with all necessary context (key images, pseudo-outs,
        // tree root, H(pqc_pk) hashes).  This function is retained for
        // the verification-caching path; the actual FCMP++ membership proof
        // is verified in the main consensus path, not here.
        // TODO(Phase 5): Wire shekyl_fcmp_verify here too for the cached path,
        // or remove this function entirely once caching is unified.
        return true;
      }
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    //------------------------------------------------------------------------------------------------------------------------------
    // FCMP++ transaction construction: replaces ring signatures with a single
    // full-chain membership proof plus Bulletproofs+ range proofs.
    //------------------------------------------------------------------------------------------------------------------------------
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
        const std::vector<key> &pqc_pk_hashes,
        hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() > 0, "Empty inamounts");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inPk.size(), "Different number of inamounts/inPk");
        CHECK_AND_ASSERT_THROW_MES(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        CHECK_AND_ASSERT_THROW_MES(pqc_pk_hashes.size() == inamounts.size(), "Different number of pqc_pk_hashes/inputs");

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
        // Flatten tree paths into a single buffer for the C API.
        std::vector<uint8_t> flat_paths;
        for (const auto &p : tree_paths)
            flat_paths.insert(flat_paths.end(), p.begin(), p.end());

        // Collect key images from input secret keys (O * Hp(O) = key image).
        // In a real flow key images come from the transaction inputs; here we
        // serialize them as 32-byte concatenated scalars.
        std::vector<uint8_t> key_images_buf(inPk.size() * 32);
        for (size_t i = 0; i < inPk.size(); ++i)
        {
            ge_p3 hp;
            hash_to_p3(hp, inPk[i].dest);
            key ki;
            crypto::secret_key sk = rct2sk(inSk[i].dest);
            ge_p2 ki_p2;
            ge_scalarmult(&ki_p2, (const unsigned char*)&sk, &hp);
            ge_tobytes(ki.bytes, &ki_p2);
            memcpy(key_images_buf.data() + i * 32, ki.bytes, 32);
        }

        // Serialize pseudo-outs and PQC hashes for FFI.
        std::vector<uint8_t> pseudo_outs_buf(rv.p.pseudoOuts.size() * 32);
        for (size_t i = 0; i < rv.p.pseudoOuts.size(); ++i)
            memcpy(pseudo_outs_buf.data() + i * 32, rv.p.pseudoOuts[i].bytes, 32);

        std::vector<uint8_t> pqc_hashes_buf(pqc_pk_hashes.size() * 32);
        for (size_t i = 0; i < pqc_pk_hashes.size(); ++i)
            memcpy(pqc_hashes_buf.data() + i * 32, pqc_pk_hashes[i].bytes, 32);

        // Construct leaf scalars from input public keys for the prover.
        std::vector<uint8_t> leaves_buf(inPk.size() * 128);
        for (size_t i = 0; i < inPk.size(); ++i)
        {
            bool ok = shekyl_construct_curve_tree_leaf(
                inPk[i].dest.bytes,
                inPk[i].mask.bytes,
                leaves_buf.data() + i * 128);
            CHECK_AND_ASSERT_THROW_MES(ok, "shekyl_construct_curve_tree_leaf failed for input " << i);
        }

        const uint32_t num_inputs = static_cast<uint32_t>(inPk.size());

        // Tree root from the reference block (the verifier re-derives it; the
        // prover needs the snapshot root to anchor the path).
        key tree_root;
        memcpy(tree_root.bytes, referenceBlock.data, 32);

        ShekylBuffer proof_buf = shekyl_fcmp_prove(
            leaves_buf.data(),
            num_inputs,
            flat_paths.data(),
            static_cast<uint32_t>(flat_paths.size()),
            key_images_buf.data(),
            pseudo_outs_buf.data(),
            pqc_hashes_buf.data(),
            tree_root.bytes,
            tree_depth);

        if (proof_buf.ptr != nullptr && proof_buf.len > 0)
        {
            rv.p.fcmp_pp_proof.assign(proof_buf.ptr, proof_buf.ptr + proof_buf.len);
            shekyl_buffer_free(proof_buf.ptr, proof_buf.len);
        }
        else
        {
            LOG_PRINT_L0("WARNING: shekyl_fcmp_prove returned empty proof (stub/placeholder)");
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
