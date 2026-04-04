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
#include "bulletproofs.h"
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
    rct::Bulletproof make_dummy_bulletproof(const std::vector<uint64_t> &outamounts, rct::keyV &C, rct::keyV &masks)
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

        return rct::Bulletproof{rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I), I, I, I};
    }

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

    rct::clsag make_dummy_clsag(size_t ring_size)
    {
        const rct::key I = rct::identity();
        const size_t n_scalars = ring_size;
        return rct::clsag{rct::keyV(n_scalars, I), I, I, I};
    }
}

namespace rct {
    Bulletproof proveRangeBulletproof(keyV &C, keyV &masks, const std::vector<uint64_t> &amounts, epee::span<const key> sk, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
        masks.resize(amounts.size());
        for (size_t i = 0; i < masks.size(); ++i)
            masks[i] = hwdev.genCommitmentMask(sk[i]);
        Bulletproof proof = bulletproof_PROVE(amounts, masks);
        CHECK_AND_ASSERT_THROW_MES(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproof(const Bulletproof &proof)
    {
      try { return bulletproof_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproof(const std::vector<const Bulletproof*> &proofs)
    {
      try { return bulletproof_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
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

    // Generate a CLSAG signature
    // See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
    //
    // The keys are set as follows:
    //   P[l] == p*G
    //   C[l] == z*G
    //   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l, hw::device &hwdev) {
        clsag sig;
        size_t n = P.size(); // ring size
        CHECK_AND_ASSERT_THROW_MES(n == C.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(n == C_nonzero.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(l < n, "Signing index out of range!");

        // Key images
        ge_p3 H_p3;
        hash_to_p3(H_p3,P[l]);
        key H;
        ge_p3_tobytes(H.bytes,&H_p3);

        key D;

        // Initial values
        key a;
        key aG;
        key aH;

        hwdev.clsag_prepare(p,z,sig.I,D,H,a,aG,aH);

        geDsmp I_precomp;
        geDsmp D_precomp;
        precomp(I_precomp.k,sig.I);
        precomp(D_precomp.k,D);

        // Offset key image
        scalarmultKey(sig.D,D,INV_EIGHT);

        // Aggregation hashes
        keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        sc_0(mu_P_to_hash[0].bytes);
        memcpy(mu_P_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
        sc_0(mu_C_to_hash[0].bytes);
        memcpy(mu_C_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
        for (size_t i = 1; i < n+1; ++i) {
            mu_P_to_hash[i] = P[i-1];
            mu_C_to_hash[i] = P[i-1];
        }
        for (size_t i = n+1; i < 2*n+1; ++i) {
            mu_P_to_hash[i] = C_nonzero[i-n-1];
            mu_C_to_hash[i] = C_nonzero[i-n-1];
        }
        mu_P_to_hash[2*n+1] = sig.I;
        mu_P_to_hash[2*n+2] = sig.D;
        mu_P_to_hash[2*n+3] = C_offset;
        mu_C_to_hash[2*n+1] = sig.I;
        mu_C_to_hash[2*n+2] = sig.D;
        mu_C_to_hash[2*n+3] = C_offset;
        key mu_P, mu_C;
        mu_P = hash_to_scalar(mu_P_to_hash);
        mu_C = hash_to_scalar(mu_C_to_hash);

        // Initial commitment
        keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, aG, aH
        key c;
        sc_0(c_to_hash[0].bytes);
        memcpy(c_to_hash[0].bytes,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
        for (size_t i = 1; i < n+1; ++i)
        {
            c_to_hash[i] = P[i-1];
            c_to_hash[i+n] = C_nonzero[i-1];
        }
        c_to_hash[2*n+1] = C_offset;
        c_to_hash[2*n+2] = message;

        c_to_hash[2*n+3] = aG;
        c_to_hash[2*n+4] = aH;

        hwdev.clsag_hash(c_to_hash,c);
        
        size_t i;
        i = (l + 1) % n;
        if (i == 0)
            copy(sig.c1, c);

        // Decoy indices
        sig.s = keyV(n);
        key c_new;
        key L;
        key R;
        key c_p; // = c[i]*mu_P
        key c_c; // = c[i]*mu_C
        geDsmp P_precomp;
        geDsmp C_precomp;
        geDsmp H_precomp;
        ge_p3 Hi_p3;

        while (i != l) {
            sig.s[i] = skGen();
            sc_0(c_new.bytes);
            sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
            sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

            // Precompute points
            precomp(P_precomp.k,P[i]);
            precomp(C_precomp.k,C[i]);

            // Compute L
            addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

            // Compute R
            hash_to_p3(Hi_p3,P[i]);
            ge_dsm_precomp(H_precomp.k, &Hi_p3);
            addKeys_aAbBcC(R,sig.s[i],H_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;
            hwdev.clsag_hash(c_to_hash,c_new);
            copy(c,c_new);
            
            i = (i + 1) % n;
            if (i == 0)
                copy(sig.c1,c);
        }

        // Compute final scalar
        hwdev.clsag_sign(c,a,p,z,mu_P,mu_C,sig.s[l]);
        memwipe(&a, sizeof(key));

        return sig;
    }

    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l) {
        return CLSAG_Gen(message, P, p, C, z, C_nonzero, C_offset, l, hw::get_device("default"));
    }

    key get_pre_mlsag_hash(const rctSig &rv, hw::device &hwdev)
    {
      keyV hashes;
      hashes.reserve(3);
      hashes.push_back(rv.message);
      crypto::hash h;

      std::stringstream ss;
      binary_archive<true> ba(ss);
      CHECK_AND_ASSERT_THROW_MES(!rv.mixRing.empty(), "Empty mixRing");
      const size_t inputs = is_rct_simple(rv.type) ? rv.mixRing.size() : rv.mixRing[0].size();
      const size_t outputs = rv.ecdhInfo.size();
      key prehash;
      CHECK_AND_ASSERT_THROW_MES(const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs),
          "Failed to serialize rctSigBase");
      cryptonote::get_blob_hash(ss.str(), h);
      hashes.push_back(hash2rct(h));

      keyV kv;
      if (rv.type == RCTTypeCLSAG)
      {
        kv.reserve((6*2+9) * rv.p.bulletproofs.size());
        for (const auto &p: rv.p.bulletproofs)
        {
          kv.push_back(p.A);
          kv.push_back(p.S);
          kv.push_back(p.T1);
          kv.push_back(p.T2);
          kv.push_back(p.taux);
          kv.push_back(p.mu);
          for (size_t n = 0; n < p.L.size(); ++n)
            kv.push_back(p.L[n]);
          for (size_t n = 0; n < p.R.size(); ++n)
            kv.push_back(p.R[n]);
          kv.push_back(p.a);
          kv.push_back(p.b);
          kv.push_back(p.t);
        }
      }
      else if (rv.type == RCTTypeBulletproofPlus)
      {
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
      }
      else
      {
        ASSERT_MES_AND_THROW("Unsupported RCT type in get_pre_mlsag_hash: " << rv.type);
      }
      hashes.push_back(cn_fast_hash(kv));
      hwdev.mlsag_prehash(ss.str(), inputs, outputs, hashes, rv.outPk, prehash);
      return  prehash;
    }

    clsag proveRctCLSAGSimple(const key &message, const ctkeyV &pubs, const ctkey &inSk, const key &a, const key &Cout, unsigned int index, hw::device &hwdev) {
        //setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        keyV tmp(rows + 1);
        keyV sk(rows + 1);
        keyM M(cols, tmp);

        keyV P, C, C_nonzero;
        P.reserve(pubs.size());
        C.reserve(pubs.size());
        C_nonzero.reserve(pubs.size());
        for (const ctkey &k: pubs)
        {
            P.push_back(k.dest);
            C_nonzero.push_back(k.mask);
            rct::key tmp;
            subKeys(tmp, k.mask, Cout);
            C.push_back(tmp);
        }

        sk[0] = copy(inSk.dest);
        sc_sub(sk[1].bytes, inSk.mask.bytes, a.bytes);
        clsag result = CLSAG_Gen(message, P, sk[0], C, sk[1], C_nonzero, Cout, index, hwdev);
        memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }

    bool verRctCLSAGSimple(const key &message, const clsag &sig, const ctkeyV & pubs, const key & C_offset) {
        try
        {
            PERF_TIMER(verRctCLSAGSimple);
            const size_t n = pubs.size();

            // Check data
            CHECK_AND_ASSERT_MES(n >= 1, false, "Empty pubs");
            CHECK_AND_ASSERT_MES(n == sig.s.size(), false, "Signature scalar vector is the wrong size!");
            for (size_t i = 0; i < n; ++i)
                CHECK_AND_ASSERT_MES(sc_check(sig.s[i].bytes) == 0, false, "Bad signature scalar!");
            CHECK_AND_ASSERT_MES(sc_check(sig.c1.bytes) == 0, false, "Bad signature commitment!");
            CHECK_AND_ASSERT_MES(!(sig.I == rct::identity()), false, "Bad key image!");

            // Cache commitment offset for efficient subtraction later
            ge_p3 C_offset_p3;
            CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&C_offset_p3, C_offset.bytes) == 0, false, "point conv failed");
            ge_cached C_offset_cached;
            ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

            // Prepare key images
            key c = copy(sig.c1);
            key D_8 = scalarmult8(sig.D);
            CHECK_AND_ASSERT_MES(!(D_8 == rct::identity()), false, "Bad auxiliary key image!");
            geDsmp I_precomp;
            geDsmp D_precomp;
            precomp(I_precomp.k,sig.I);
            precomp(D_precomp.k,D_8);

            // Aggregation hashes
            keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            sc_0(mu_P_to_hash[0].bytes);
            memcpy(mu_P_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
            sc_0(mu_C_to_hash[0].bytes);
            memcpy(mu_C_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
            for (size_t i = 1; i < n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-1].dest;
                mu_C_to_hash[i] = pubs[i-1].dest;
            }
            for (size_t i = n+1; i < 2*n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-n-1].mask;
                mu_C_to_hash[i] = pubs[i-n-1].mask;
            }
            mu_P_to_hash[2*n+1] = sig.I;
            mu_P_to_hash[2*n+2] = sig.D;
            mu_P_to_hash[2*n+3] = C_offset;
            mu_C_to_hash[2*n+1] = sig.I;
            mu_C_to_hash[2*n+2] = sig.D;
            mu_C_to_hash[2*n+3] = C_offset;
            key mu_P, mu_C;
            mu_P = hash_to_scalar(mu_P_to_hash);
            mu_C = hash_to_scalar(mu_C_to_hash);

            // Set up round hash
            keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, L, R
            sc_0(c_to_hash[0].bytes);
            memcpy(c_to_hash[0].bytes,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
            for (size_t i = 1; i < n+1; ++i)
            {
                c_to_hash[i] = pubs[i-1].dest;
                c_to_hash[i+n] = pubs[i-1].mask;
            }
            c_to_hash[2*n+1] = C_offset;
            c_to_hash[2*n+2] = message;
            key c_p; // = c[i]*mu_P
            key c_c; // = c[i]*mu_C
            key c_new;
            key L;
            key R;
            geDsmp P_precomp;
            geDsmp C_precomp;
            size_t i = 0;
            ge_p3 hash8_p3;
            geDsmp hash_precomp;
            ge_p3 temp_p3;
            ge_p1p1 temp_p1;

            while (i < n) {
                sc_0(c_new.bytes);
                sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
                sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

                // Precompute points for L/R
                precomp(P_precomp.k,pubs[i].dest);

                CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&temp_p3, pubs[i].mask.bytes) == 0, false, "point conv failed");
                ge_sub(&temp_p1,&temp_p3,&C_offset_cached);
                ge_p1p1_to_p3(&temp_p3,&temp_p1);
                ge_dsm_precomp(C_precomp.k,&temp_p3);

                // Compute L
                addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

                // Compute R
                hash_to_p3(hash8_p3,pubs[i].dest);
                ge_dsm_precomp(hash_precomp.k, &hash8_p3);
                addKeys_aAbBcC(R,sig.s[i],hash_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

                c_to_hash[2*n+3] = L;
                c_to_hash[2*n+4] = R;
                c_new = hash_to_scalar(c_to_hash);
                CHECK_AND_ASSERT_MES(!(c_new == rct::zero()), false, "Bad signature hash");
                copy(c,c_new);

                i = i + 1;
            }
            sc_sub(c_new.bytes,c.bytes,sig.c1.bytes);
            return sc_isnonzero(c_new.bytes) == 0;
        }
        catch (...) { return false; }
    }


    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).    
    void getKeyFromBlockchain(ctkey & a, size_t reference_index) {
        a.mask = pkGen();
        a.dest = pkGen();
    }

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).     
    xmr_amount populateFromBlockchainSimple(ctkeyV & mixRing, const ctkey & inPk, int mixin) {
        int index = randXmrAmount(mixin);
        int i = 0;
        for (i = 0; i <= mixin; i++) {
            if (i != index) {
                getKeyFromBlockchain(mixRing[i], (size_t)randXmrAmount(1000));
            } else {
                mixRing[i] = inPk;
            }
        }
        return index;
    }

    //RCT simple    
    //for post-rct only
    rctSig genRctSimple(const key &message, const ctkeyV & inSk, const keyV & destinations, const vector<xmr_amount> &inamounts, const vector<xmr_amount> &outamounts, xmr_amount txnFee, const ctkeyM & mixRing, const keyV &amount_keys, const std::vector<unsigned int> & index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev) {
        CHECK_AND_ASSERT_THROW_MES(rct_config.range_proof_type > RangeProofBorromean, "Borromean range proofs are not supported");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() > 0, "Empty inamounts");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
        CHECK_AND_ASSERT_THROW_MES(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        CHECK_AND_ASSERT_THROW_MES(index.size() == inSk.size(), "Different number of index/inSk");
        CHECK_AND_ASSERT_THROW_MES(mixRing.size() == inSk.size(), "Different number of mixRing/inSk");
        for (size_t n = 0; n < mixRing.size(); ++n) {
          CHECK_AND_ASSERT_THROW_MES(index[n] < mixRing[n].size(), "Bad index into mixRing");
        }

        rctSig rv;
        switch (rct_config.bp_version)
        {
          case 0:
          case 4:
            rv.type = RCTTypeBulletproofPlus;
            break;
          case 3:
            rv.type = RCTTypeCLSAG;
            break;
          default:
            ASSERT_MES_AND_THROW("Unsupported BP version: " << rct_config.bp_version);
        }

        rv.message = message;
        rv.outPk.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());

        size_t i;
        keyV masks(destinations.size());
        outSk.resize(destinations.size());
        for (i = 0; i < destinations.size(); i++) {
            rv.outPk[i].dest = copy(destinations[i]);
        }

        rv.p.bulletproofs.clear();
        rv.p.bulletproofs_plus.clear();
        const bool plus = is_rct_bulletproof_plus(rv.type);
        size_t n_amounts = outamounts.size();
        size_t amounts_proved = 0;
        if (rct_config.range_proof_type == RangeProofPaddedBulletproof)
        {
            rct::keyV C, masks;
            if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
            {
                if (plus)
                  rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(outamounts, C, masks));
                else
                  rv.p.bulletproofs.push_back(make_dummy_bulletproof(outamounts, C, masks));
            }
            else
            {
                const epee::span<const key> keys{&amount_keys[0], amount_keys.size()};
                if (plus)
                  rv.p.bulletproofs_plus.push_back(proveRangeBulletproofPlus(C, masks, outamounts, keys, hwdev));
                else
                  rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, outamounts, keys, hwdev));
                #ifdef DBG
                if (plus)
                  CHECK_AND_ASSERT_THROW_MES(verBulletproofPlus(rv.p.bulletproofs_plus.back()), "verBulletproofPlus failed on newly created proof");
                else
                  CHECK_AND_ASSERT_THROW_MES(verBulletproof(rv.p.bulletproofs.back()), "verBulletproof failed on newly created proof");
                #endif
            }
            for (i = 0; i < outamounts.size(); ++i)
            {
                rv.outPk[i].mask = rct::scalarmult8(C[i]);
                outSk[i].mask = masks[i];
            }
        }
        else while (amounts_proved < n_amounts)
        {
            size_t batch_size = 1;
            if (rct_config.range_proof_type == RangeProofMultiOutputBulletproof)
              while (batch_size * 2 + amounts_proved <= n_amounts && batch_size * 2 <= (plus ? BULLETPROOF_PLUS_MAX_OUTPUTS : BULLETPROOF_MAX_OUTPUTS))
                batch_size *= 2;
            rct::keyV C, masks;
            std::vector<uint64_t> batch_amounts(batch_size);
            for (i = 0; i < batch_size; ++i)
              batch_amounts[i] = outamounts[i + amounts_proved];
            if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
            {
                if (plus)
                  rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(batch_amounts, C, masks));
                else
                  rv.p.bulletproofs.push_back(make_dummy_bulletproof(batch_amounts, C, masks));
            }
            else
            {
                const epee::span<const key> keys{&amount_keys[amounts_proved], batch_size};
                if (plus)
                  rv.p.bulletproofs_plus.push_back(proveRangeBulletproofPlus(C, masks, batch_amounts, keys, hwdev));
                else
                  rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, batch_amounts, keys, hwdev));
            #ifdef DBG
                if (plus)
                  CHECK_AND_ASSERT_THROW_MES(verBulletproofPlus(rv.p.bulletproofs_plus.back()), "verBulletproofPlus failed on newly created proof");
                else
                  CHECK_AND_ASSERT_THROW_MES(verBulletproof(rv.p.bulletproofs.back()), "verBulletproof failed on newly created proof");
            #endif
            }
            for (i = 0; i < batch_size; ++i)
            {
              rv.outPk[i + amounts_proved].mask = rct::scalarmult8(C[i]);
              outSk[i + amounts_proved].mask = masks[i];
            }
            amounts_proved += batch_size;
        }

        key sumout = zero();
        for (i = 0; i < outSk.size(); ++i)
        {
            sc_add(sumout.bytes, outSk[i].mask.bytes, sumout.bytes);

            rv.ecdhInfo[i].mask = copy(outSk[i].mask);
            rv.ecdhInfo[i].amount = d2h(outamounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], true);
        }
            
        rv.txnFee = txnFee;
        rv.mixRing = mixRing;
        rv.p.pseudoOuts.resize(inamounts.size());
        rv.p.CLSAGs.resize(inamounts.size());
        key sumpouts = zero();
        keyV a(inamounts.size());
        for (i = 0 ; i < inamounts.size() - 1; i++) {
            skGen(a[i]);
            sc_add(sumpouts.bytes, a[i].bytes, sumpouts.bytes);
            genC(rv.p.pseudoOuts[i], a[i], inamounts[i]);
        }
        sc_sub(a[i].bytes, sumout.bytes, sumpouts.bytes);
        genC(rv.p.pseudoOuts[i], a[i], inamounts[i]);
        DP(rv.p.pseudoOuts[i]);

        key full_message = get_pre_mlsag_hash(rv,hwdev);

        for (i = 0 ; i < inamounts.size(); i++)
        {
            if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
                rv.p.CLSAGs[i] = make_dummy_clsag(rv.mixRing[i].size());
            else
                rv.p.CLSAGs[i] = proveRctCLSAGSimple(full_message, rv.mixRing[i], inSk[i], a[i], rv.p.pseudoOuts[i], index[i], hwdev);
        }
        return rv;
    }

    rctSig genRctSimple(const key &message, const ctkeyV & inSk, const ctkeyV & inPk, const keyV & destinations, const vector<xmr_amount> &inamounts, const vector<xmr_amount> &outamounts, const keyV &amount_keys, xmr_amount txnFee, unsigned int mixin, const RCTConfig &rct_config, hw::device &hwdev) {
        std::vector<unsigned int> index;
        index.resize(inPk.size());
        ctkeyM mixRing;
        ctkeyV outSk;
        mixRing.resize(inPk.size());
        for (size_t i = 0; i < inPk.size(); ++i) {
          mixRing[i].resize(mixin+1);
          index[i] = populateFromBlockchainSimple(mixRing[i], inPk[i], mixin);
        }
        return genRctSimple(message, inSk, destinations, inamounts, outamounts, txnFee, mixRing, amount_keys, index, outSk, rct_config, hwdev);
    }

    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctSemanticsSimple(const std::vector<const rctSig*> & rvv) {
      try
      {
        PERF_TIMER(verRctSemanticsSimple);

        std::vector<const Bulletproof*> bp_proofs;
        std::vector<const BulletproofPlus*> bpp_proofs;

        for (const rctSig *rvp: rvv)
        {
          CHECK_AND_ASSERT_MES(rvp, false, "rctSig pointer is NULL");
          const rctSig &rv = *rvp;
          CHECK_AND_ASSERT_MES(rv.type == RCTTypeCLSAG || rv.type == RCTTypeBulletproofPlus,
              false, "verRctSemanticsSimple called on unsupported rctSig type");
          const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
          if (bulletproof_plus)
            CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus), false, "Mismatched sizes of outPk and bulletproofs_plus");
          else
            CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs), false, "Mismatched sizes of outPk and bulletproofs");
          CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs are not empty for CLSAG");
          CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.CLSAGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs");
          CHECK_AND_ASSERT_MES(rv.pseudoOuts.empty(), false, "rv.pseudoOuts is not empty");
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");
        }

        for (const rctSig *rvp: rvv)
        {
          const rctSig &rv = *rvp;
          const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
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

          if (bulletproof_plus)
          {
            for (size_t i = 0; i < rv.p.bulletproofs_plus.size(); i++)
              bpp_proofs.push_back(&rv.p.bulletproofs_plus[i]);
          }
          else
          {
            for (size_t i = 0; i < rv.p.bulletproofs.size(); i++)
              bp_proofs.push_back(&rv.p.bulletproofs[i]);
          }
        }
        if (!bpp_proofs.empty() && !verBulletproofPlus(bpp_proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verified failed");
          return false;
        }
        if (!bp_proofs.empty() && !verBulletproof(bp_proofs))
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

    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctNonSemanticsSimple(const rctSig & rv) {
      try
      {
        PERF_TIMER(verRctNonSemanticsSimple);

        CHECK_AND_ASSERT_MES(rv.type == RCTTypeCLSAG || rv.type == RCTTypeBulletproofPlus,
            false, "verRctNonSemanticsSimple called on unsupported rctSig type");
        CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.mixRing.size(), false, "Mismatched sizes of rv.p.pseudoOuts and mixRing");

        const size_t threads = std::max(rv.outPk.size(), rv.mixRing.size());

        std::deque<bool> results(threads);
        tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
        tools::threadpool::waiter waiter(tpool);

        const keyV &pseudoOuts = rv.p.pseudoOuts;

        const key message = get_pre_mlsag_hash(rv, hw::get_device("default"));

        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0 ; i < rv.mixRing.size() ; i++) {
          tpool.submit(&waiter, [&, i] {
              results[i] = verRctCLSAGSimple(message, rv.p.CLSAGs[i], rv.mixRing[i], pseudoOuts[i]);
          });
        }
        if (!waiter.wait())
          return false;

        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("verRctCLSAGSimple failed for input " << i);
            return false;
          }
        }

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
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeCLSAG || rv.type == RCTTypeBulletproofPlus,
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
