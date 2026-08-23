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
#include "ct_semantics.h"
#include "bulletproofs_plus.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

using namespace crypto;
using namespace std;

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "fcmp"

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace ct {
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

    void fill_construct_tx_rct_stub(CtSig &rv, const key &message, xmr_amount txnFee,
        const crypto::hash &referenceBlock, const std::vector<xmr_amount> &inamounts,
        const std::vector<xmr_amount> &outamounts, const keyV &destinations)
    {
        CHECK_AND_ASSERT_THROW_MES(!inamounts.empty(), "fill_construct_tx_rct_stub: no inputs");
        const size_t n_out = outamounts.size();
        const size_t n_in = inamounts.size();
        CHECK_AND_ASSERT_THROW_MES(destinations.size() == n_out, "fill_construct_tx_rct_stub: destinations/outamounts mismatch");

        rv.type = CTTypeFcmpPlusPlusPqc;
        rv.message = message;
        rv.txnFee = txnFee;
        rv.referenceBlock = referenceBlock;
        rv.p.curve_trees_tree_depth = 0;
        rv.p.fcmp_pp_proof.clear();

        rv.outPk.resize(n_out);
        rv.enc_amounts.resize(n_out);
        rv.enc_labels.resize(n_out);
        for (size_t i = 0; i < n_out; ++i)
            rv.outPk[i].dest = copy(destinations[i]);

        keyV C, masks;
        rv.p.bulletproofs_plus.clear();
        rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(outamounts, C, masks));
        for (size_t i = 0; i < n_out; ++i)
            rv.outPk[i].mask = scalarmult8(C[i]);

        key sumout = zero();
        for (size_t i = 0; i < n_out; ++i)
            sc_add(sumout.bytes, masks[i].bytes, sumout.bytes);

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

    key get_tx_prehash(const CtSig &rv, hw::device &hwdev)
    {
      keyV hashes;
      hashes.reserve(3);
      hashes.push_back(rv.message);
      crypto::hash h;

      std::stringstream ss;
      binary_archive<true> ba(ss);
      const size_t inputs = rv.p.pseudoOuts.size();
      const size_t outputs = rv.enc_amounts.size();
      key prehash;
      CHECK_AND_ASSERT_THROW_MES(const_cast<CtSig&>(rv).serialize_ctsig_base(ba, inputs, outputs),
          "Failed to serialize CtSigBase");
      cryptonote::get_blob_hash(ss.str(), h);
      hashes.push_back(hash2rct(h));

      keyV kv;
      CHECK_AND_ASSERT_THROW_MES(rv.type == CTTypeFcmpPlusPlusPqc, "Unsupported CT type in get_tx_prehash: " << rv.type);
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
      hwdev.tx_prehash(ss.str(), inputs, outputs, hashes, rv.outPk, prehash);
      return  prehash;
    }

    //ver FCMP++ simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verCtSemanticsSimple(const std::vector<const CtSig*> & rvv) {
      try
      {
        PERF_TIMER(verCtSemanticsSimple);

        std::vector<const BulletproofPlus*> bpp_proofs;

        for (const CtSig *rvp: rvv)
        {
          CHECK_AND_ASSERT_MES(rvp, false, "CtSig pointer is NULL");
          const CtSig &rv = *rvp;
          CHECK_AND_ASSERT_MES(rv.type == CTTypeFcmpPlusPlusPqc,
              false, "verCtSemanticsSimple called on unsupported CtSig type");
          CHECK_AND_ASSERT_MES(!rv.p.fcmp_pp_proof.empty(),
              false, "FCMP++ proof is empty");
          CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus), false, "Mismatched sizes of outPk and bulletproofs_plus");
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.enc_amounts.size(), false, "Mismatched sizes of outPk and rv.enc_amounts");
          CHECK_AND_ASSERT_MES(rv.enc_labels.size() == rv.enc_amounts.size(), false, "Mismatched sizes of enc_labels and rv.enc_amounts");
        }

        for (const CtSig *rvp: rvv)
        {
          const CtSig &rv = *rvp;

          // CT cleartext balance `sum(pseudoOuts) = sum(outPk masks) + fee*H`,
          // single-sourced in Rust (`shekyl-ct-balance::verify_ct_balance`) and
          // shared with construct (`shekyl-tx-builder`) and the archival bond-post
          // path, so the three cannot diverge. Canonical prime-order commitment
          // points per `GENESIS_TX_WIRE_FORMAT.md` §2.3 (the native
          // `addKeys`/`equalKeys` block this replaces summed raw points).
          std::vector<uint8_t> pseudo_flat(rv.p.pseudoOuts.size() * 32);
          for (size_t i = 0; i < rv.p.pseudoOuts.size(); ++i)
            memcpy(pseudo_flat.data() + i * 32, rv.p.pseudoOuts[i].bytes, 32);
          std::vector<uint8_t> mask_flat(rv.outPk.size() * 32);
          for (size_t i = 0; i < rv.outPk.size(); ++i)
            memcpy(mask_flat.data() + i * 32, rv.outPk[i].mask.bytes, 32);
          const uint8_t balance_rc = shekyl_verify_ct_balance(
              pseudo_flat.empty() ? nullptr : pseudo_flat.data(),
              rv.p.pseudoOuts.size(),
              mask_flat.empty() ? nullptr : mask_flat.data(),
              rv.outPk.size(),
              rv.txnFee);
          if (balance_rc != SHEKYL_CT_BALANCE_OK) {
            LOG_PRINT_L1("Sum check failed (rc=" << static_cast<unsigned>(balance_rc) << ")");
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
        LOG_PRINT_L1("Error in verCtSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verCtSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    bool verCtSemanticsSimple(const CtSig & rv)
    {
      return verCtSemanticsSimple(std::vector<const CtSig*>(1, &rv));
    }

    // Shared CT-balance + aggregate-range tail for the archival bond-post and
    // reward-emission semantics checks. The balance FFI, canonical-BPP layout
    // check, flatten loops, and range-proof verify are identical for both — only
    // the (credit, debit) operands and each caller's structural prologue differ,
    // so the common logic lives here once. `what` labels the log lines. Any
    // divergence must be made here, not forked into a second copy.
    static bool verArchivalCtBalanceAndRange(const CtSig &rv,
        const uint64_t bond_credit, const uint64_t bond_debit, const char *what)
    {
      CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus),
          false, "Mismatched sizes of outPk and bulletproofs_plus");
      CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.enc_amounts.size(), false,
          "Mismatched sizes of outPk and rv.enc_amounts");
      CHECK_AND_ASSERT_MES(rv.enc_labels.size() == rv.enc_amounts.size(), false,
          "Mismatched sizes of enc_labels and rv.enc_amounts");
      if (!rv.p.bulletproofs_plus.empty()
          && !is_canonical_bulletproof_plus_layout(rv.p.bulletproofs_plus))
      {
        LOG_PRINT_L1(what << " bulletproof_plus is not canonical");
        return false;
      }
      std::vector<uint8_t> pseudo_flat;
      pseudo_flat.reserve(rv.p.pseudoOuts.size() * 32);
      for (const key &k : rv.p.pseudoOuts)
        pseudo_flat.insert(pseudo_flat.end(), k.bytes, k.bytes + 32);
      std::vector<uint8_t> mask_flat;
      mask_flat.reserve(rv.outPk.size() * 32);
      for (const ctkey &op : rv.outPk)
        mask_flat.insert(mask_flat.end(), op.mask.bytes, op.mask.bytes + 32);
      const uint8_t balance_rc = shekyl_archival_verify_bond_post_ct_balance(
          pseudo_flat.empty() ? nullptr : pseudo_flat.data(),
          rv.p.pseudoOuts.size(),
          mask_flat.empty() ? nullptr : mask_flat.data(),
          rv.outPk.size(),
          rv.txnFee,
          bond_credit,
          bond_debit);
      if (balance_rc != SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK)
      {
        LOG_PRINT_L1(what << " sum check failed (rc=" << static_cast<unsigned>(balance_rc) << ")");
        return false;
      }

      std::vector<const BulletproofPlus*> bpp_proofs;
      for (size_t i = 0; i < rv.p.bulletproofs_plus.size(); ++i)
        bpp_proofs.push_back(&rv.p.bulletproofs_plus[i]);
      if (!bpp_proofs.empty() && !verBulletproofPlus(bpp_proofs))
      {
        LOG_PRINT_L1(what << " aggregate range proof verification failed");
        return false;
      }
      return true;
    }

    bool verCtSemanticsBondPost(const CtSig &rv, const uint64_t bond_credit, const uint64_t bond_debit)
    {
      try
      {
        CHECK_AND_ASSERT_MES(rv.type == CTTypeFcmpPlusPlusPqc, false,
            "verCtSemanticsBondPost called on unsupported CtSig type");
        CHECK_AND_ASSERT_MES(!rv.p.fcmp_pp_proof.empty(), false,
            "verCtSemanticsBondPost requires non-empty FCMP++ proof");
        // Bond-post CT balance: credit = bond_credit, debit = bond_debit.
        return verArchivalCtBalanceAndRange(rv, bond_credit, bond_debit, "Bond-post");
      }
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verCtSemanticsBondPost: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verCtSemanticsBondPost, but not an actual exception");
        return false;
      }
    }

    bool verCtSemanticsEmission(const CtSig &rv, const uint64_t total_reward, const size_t fee_input_count)
    {
      try
      {
        CHECK_AND_ASSERT_MES(rv.type == CTTypeFcmpPlusPlusPqc, false,
            "verCtSemanticsEmission called on unsupported CtSig type");
        // Q11: fee inputs are optional. The FCMP++ proof authorizes exactly the
        // txin_to_key co-residents — present iff there are any (a proof with no
        // spends, or spends with no proof, are both malformed).
        CHECK_AND_ASSERT_MES(rv.p.fcmp_pp_proof.empty() == (fee_input_count == 0), false,
            "emission FCMP++ proof presence must match fee-input count");
        CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == fee_input_count, false,
            "emission pseudoOuts must match fee-input count");
        CHECK_AND_ASSERT_MES(total_reward > 0, false,
            "emission total_reward must be positive (wire positivity)");
        // CT balance with the mint on the input side:
        //   sum(pseudoOuts) + total_reward*H = sum(out masks) + fee*H.
        // Same single-sourced tail as bond-post; the mint rides the debit slot
        // (left-hand side), credit stays 0.
        return verArchivalCtBalanceAndRange(rv, /*bond_credit=*/0,
            /*bond_debit=*/total_reward, "Emission");
      }
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verCtSemanticsEmission: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verCtSemanticsEmission, but not an actual exception");
        return false;
      }
    }

    bool verCtSemanticsFeeOnly(const CtSig &rv)
    {
      try
      {
        CHECK_AND_ASSERT_MES(rv.type == CTTypeFcmpPlusPlusPqc, false,
            "verCtSemanticsFeeOnly called on unsupported CtSig type");
        CHECK_AND_ASSERT_MES(rv.p.fcmp_pp_proof.empty(), false, "FCMP++ proof must be empty");
        CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.empty(), false, "pseudoOuts must be empty");
        CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus),
            false, "Mismatched sizes of outPk and bulletproofs_plus");
        CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.enc_amounts.size(), false,
            "Mismatched sizes of outPk and rv.enc_amounts");
        CHECK_AND_ASSERT_MES(rv.enc_labels.size() == rv.enc_amounts.size(), false,
            "Mismatched sizes of enc_labels and rv.enc_amounts");

        // Fee-only CT balance: `sum(outPk masks) + fee*H = identity` — the general
        // balance with an empty pseudoOut side (asserted above), through the same
        // single-sourced `shekyl_verify_ct_balance` (§2.3).
        std::vector<uint8_t> mask_flat(rv.outPk.size() * 32);
        for (size_t i = 0; i < rv.outPk.size(); ++i)
          memcpy(mask_flat.data() + i * 32, rv.outPk[i].mask.bytes, 32);
        const uint8_t balance_rc = shekyl_verify_ct_balance(
            nullptr, 0,
            mask_flat.empty() ? nullptr : mask_flat.data(),
            rv.outPk.size(),
            rv.txnFee);
        if (balance_rc != SHEKYL_CT_BALANCE_OK)
        {
          LOG_PRINT_L1("Sum check failed (rc=" << static_cast<unsigned>(balance_rc) << ")");
          return false;
        }

        std::vector<const BulletproofPlus*> bpp_proofs;
        for (size_t i = 0; i < rv.p.bulletproofs_plus.size(); ++i)
          bpp_proofs.push_back(&rv.p.bulletproofs_plus[i]);
        if (!bpp_proofs.empty() && !verBulletproofPlus(bpp_proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verification failed");
          return false;
        }
        return true;
      }
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verCtSemanticsFeeOnly: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verCtSemanticsFeeOnly, but not an actual exception");
        return false;
      }
    }

}
