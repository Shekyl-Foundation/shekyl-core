// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// CT-balance FFI cutover — three-class C++<->Rust differential corpus.
//
// The F-2 pre-cutover gate for GENESIS_TX_WIRE_FORMAT.md §2.3. It compares the
// inherited C++ balance oracle (the isolated addKeys/equalKeys block from
// verCtSemanticsSimple) against the Rust `shekyl_verify_ct_balance` FFI on
// identical inputs, BEFORE the C++ call site is re-pointed:
//
//   class 1  valid canonical     -> both agree (accept and reject)
//   class 2  torsion-laden       -> C++ accept, Rust reject (INVALID_POINT):
//                                   the intended tx-malleability divergence
//   class 3  non-canonical field -> characterized against ge_frombytes_vartime,
//                                   not assumed
//
// The oracle is kept live (this file does not touch ct_semantics.cpp); the cutover
// deletes the native block only once this corpus is green.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <vector>

extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "fcmp/ct_ops.h"
#include "shekyl/shekyl_ffi.h"

namespace
{
  // A known curve25519 small-order (8-torsion) point, shared with the
  // shekyl-ct-balance crate's `rejects_small_order_commitment` vector.
  ct::key torsion_point()
  {
    static const uint8_t bytes[32] = {
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
        0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa};
    ct::key k;
    std::memcpy(k.bytes, bytes, 32);
    return k;
  }

  // Deterministic mask scalar for the KAT — no RNG, so the corpus is fully
  // reproducible across runs and architectures (the differential is a
  // known-answer test, not a fuzzer). Distinct per `seed`, hashed to a scalar.
  ct::key det_mask(uint64_t seed)
  {
    // Domain-separated structured preimage: ASCII "Shekyl" followed by the seed
    // as 8-byte little-endian — a genuine concatenation (no arithmetic carry
    // into the domain bytes) — hashed to a scalar.
    uint8_t preimage[14];
    std::memcpy(preimage, "Shekyl", 6);
    for (int i = 0; i < 8; ++i)
      preimage[6 + i] = static_cast<uint8_t>(seed >> (8 * i));
    ct::key scalar;
    ct::hash_to_scalar(scalar, preimage, sizeof(preimage));
    return scalar;
  }

  // The C++ oracle: the isolated balance block from verCtSemanticsSimple
  // (ct_semantics.cpp) — sum(pseudoOuts) == sum(masks) + fee*H.
  bool cpp_oracle(const ct::keyV &pseudoOuts, const ct::keyV &masks, uint64_t fee)
  {
    ct::key sumOutpks = ct::addKeys(masks);
    const ct::key txnFeeKey = ct::scalarmultH(ct::d2h(fee));
    ct::addKeys(sumOutpks, sumOutpks, txnFeeKey);
    ct::key sumPseudoOuts = ct::addKeys(pseudoOuts);
    return ct::equalKeys(sumPseudoOuts, sumOutpks);
  }

  std::vector<uint8_t> flatten(const ct::keyV &ks)
  {
    std::vector<uint8_t> out;
    out.reserve(ks.size() * 32);
    for (const auto &k : ks)
      out.insert(out.end(), k.bytes, k.bytes + 32);
    return out;
  }

  uint8_t rust_ffi(const ct::keyV &pseudoOuts, const ct::keyV &masks, uint64_t fee)
  {
    const std::vector<uint8_t> p = flatten(pseudoOuts);
    const std::vector<uint8_t> m = flatten(masks);
    return shekyl_verify_ct_balance(p.empty() ? nullptr : p.data(), pseudoOuts.size(),
                                    m.empty() ? nullptr : m.data(), masks.size(), fee);
  }

  // ---- Class 1: valid canonical -> C++/Rust equivalence ----

  TEST(CtBalanceDifferential, class1_single_output_balanced_both_accept)
  {
    const uint64_t fee = 7;
    const ct::key m = det_mask(1);
    const ct::keyV masks = {ct::commit(100, m)};  // m*G + 100*H
    const ct::keyV pseudo = {ct::commit(107, m)}; // m*G + 107*H
    EXPECT_TRUE(cpp_oracle(pseudo, masks, fee));
    EXPECT_EQ(rust_ffi(pseudo, masks, fee), SHEKYL_CT_BALANCE_OK);
  }

  TEST(CtBalanceDifferential, class1_large_batch_balanced_both_accept)
  {
    const uint64_t fee = 3;
    ct::keyV masks, pseudo;
    for (int i = 0; i < 12; ++i)
    {
      const ct::key m = det_mask(static_cast<uint64_t>(i));
      masks.push_back(ct::commit(10 + i, m));
      pseudo.push_back(ct::commit(10 + i, m)); // identical G- and H-parts
    }
    pseudo.push_back(ct::scalarmultH(ct::d2h(fee))); // + fee*H closes the balance
    EXPECT_TRUE(cpp_oracle(pseudo, masks, fee));
    EXPECT_EQ(rust_ffi(pseudo, masks, fee), SHEKYL_CT_BALANCE_OK);
  }

  TEST(CtBalanceDifferential, class1_fee_only_shape_balanced_both_accept)
  {
    // Empty pseudoOuts (the fee-only / serve-credit shape): sum(masks) + fee*H
    // must be the identity. One mask = -(fee*H) (sign-bit negation).
    const uint64_t fee = 5;
    ct::key neg_fee_h = ct::scalarmultH(ct::d2h(fee));
    neg_fee_h.bytes[31] ^= 0x80; // negate the point
    const ct::keyV masks = {neg_fee_h};
    const ct::keyV pseudo = {};
    EXPECT_TRUE(cpp_oracle(pseudo, masks, fee));
    EXPECT_EQ(rust_ffi(pseudo, masks, fee), SHEKYL_CT_BALANCE_OK);
  }

  TEST(CtBalanceDifferential, class1_unbalanced_valid_both_reject)
  {
    const uint64_t fee = 7;
    const ct::key m = det_mask(2);
    const ct::keyV masks = {ct::commit(100, m)};
    const ct::keyV pseudo = {ct::commit(108, m)}; // off by one
    EXPECT_FALSE(cpp_oracle(pseudo, masks, fee));
    EXPECT_EQ(rust_ffi(pseudo, masks, fee), SHEKYL_CT_BALANCE_ERR_SUM_MISMATCH);
  }

  TEST(CtBalanceDifferential, class1_bond_post_regression_anchor)
  {
    // The bond-post path shares verify_ct_balance + the FFI flatten helpers, so a
    // balanced bond-post case proves the shared code did not move under the
    // rename/cutover. Bond-post balance: sum(pseudo) + debit = sum(mask) + fee + credit.
    // With fee = debit = 0: sum(pseudo) = sum(mask) + credit*H.
    const uint64_t credit = 1000;
    const ct::key m = det_mask(3);
    const ct::keyV masks = {ct::commit(0, m)};      // m*G
    const ct::keyV pseudo = {ct::commit(credit, m)}; // m*G + credit*H
    const std::vector<uint8_t> p = flatten(pseudo);
    const std::vector<uint8_t> mf = flatten(masks);
    const uint8_t rc = shekyl_archival_verify_bond_post_ct_balance(
        p.data(), 1, mf.data(), 1, /*fee*/ 0, /*bond_credit*/ credit, /*bond_debit*/ 0);
    EXPECT_EQ(rc, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK);
  }

  // ---- Class 2: torsion-laden -> intended divergence ----

  TEST(CtBalanceDifferential, class2_torsion_both_sides_cpp_accepts_rust_rejects)
  {
    // The malleability vector: a matched order-8 T on one pseudoOut and one mask.
    // The T's cancel in the sum, so the C++ oracle accepts; Rust rejects the
    // non-torsion-free points. Same economic tx, second serialization.
    const uint64_t fee = 7;
    const ct::key m = det_mask(4);
    const ct::key mask = ct::commit(100, m);
    const ct::key pseudo_pt = ct::commit(107, m);
    const ct::key t = torsion_point();
    const ct::keyV masks = {ct::addKeys(mask, t)};       // M + T
    const ct::keyV pseudo = {ct::addKeys(pseudo_pt, t)}; // P + T
    EXPECT_TRUE(cpp_oracle(pseudo, masks, fee));           // C++ accepts (T cancels)
    EXPECT_EQ(rust_ffi(pseudo, masks, fee), SHEKYL_CT_BALANCE_ERR_INVALID_POINT);
  }

  TEST(CtBalanceDifferential, class2_torsion_pseudo_only_error_precedence)
  {
    // Torsion on a pseudoOut with no matching mask T: the sum cannot balance, so
    // both reject — but Rust must reject as INVALID_POINT (the decompress check),
    // ordered ahead of SUM_MISMATCH. Pins the FFI error-precedence.
    const uint64_t fee = 7;
    const ct::key m = det_mask(5);
    const ct::key mask = ct::commit(100, m);
    const ct::key pseudo_pt = ct::commit(107, m);
    const ct::key t = torsion_point();
    const ct::keyV masks = {mask};
    const ct::keyV pseudo = {ct::addKeys(pseudo_pt, t)}; // P + T
    EXPECT_FALSE(cpp_oracle(pseudo, masks, fee));          // C++ rejects (sum differs by T)
    EXPECT_EQ(rust_ffi(pseudo, masks, fee), SHEKYL_CT_BALANCE_ERR_INVALID_POINT);
  }

  // ---- Class 3: non-canonical field encoding -> characterization ----
  //
  // "Characterize, don't assume." Feed non-canonical y-encodings through BOTH the
  // C++ oracle (ge_frombytes_vartime, inside addKeys) and the Rust FFI, and lock
  // the observed relationship. `check_cpp_decode` isolates the C++ decode from the
  // balance arithmetic so a decode failure is a clean bool, not an addKeys hazard.

  // True iff the C++ ge_frombytes_vartime path accepts this 32-byte encoding as a
  // curve point (the same decode the balance oracle's addKeys performs).
  bool cpp_decodes(const ct::key &k)
  {
    ge_p3 p3;
    return ge_frombytes_vartime(&p3, k.bytes) == 0;
  }

  // Non-canonical y-encodings to characterize. Each is fed to the C++ decode and
  // the Rust FFI; the assertions below are LOCKED to what was observed on the lane
  // (not assumed). Where both reject, the two are already in agreement and no
  // second §2.3 divergence exists; any single-sided acceptance would be a new
  // divergence to ratify.
  TEST(CtBalanceDifferential, class3_noncanonical_y_ge_p_characterized)
  {
    // y = p (= 2^255 - 19): ed ff..ff 7f.
    ct::key y_eq_p;
    std::memset(y_eq_p.bytes, 0xff, 32);
    y_eq_p.bytes[0] = 0xed;
    y_eq_p.bytes[31] = 0x7f;

    // y = p + 1: ee ff..ff 7f.
    ct::key y_p_plus_1 = y_eq_p;
    y_p_plus_1.bytes[0] = 0xee;

    for (const ct::key &nc : {y_eq_p, y_p_plus_1})
    {
      const ct::keyV pseudo = {nc};
      const ct::keyV masks = {};
      const bool cpp_ok = cpp_decodes(nc);
      const uint8_t rust = rust_ffi(pseudo, masks, 0);
      // This corpus initially caught Rust ACCEPTING y = p + 1 (dalek's decompress
      // reduces y mod p to the identity, which is torsion-free) where C++
      // ge_frombytes_vartime rejects it — a residual non-canonical-encoding
      // malleability surface. Closed by the canonical round-trip check in
      // shekyl-ct-balance::decompress_point; now both sides reject, in agreement,
      // so this class carries no additional §2.3 divergence to ratify.
      EXPECT_FALSE(cpp_ok);
      EXPECT_EQ(rust, SHEKYL_CT_BALANCE_ERR_INVALID_POINT);
    }
  }
}
