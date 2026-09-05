// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// GAP-7 escalation microbench: the SHIPPED Bp+ verifier's cost.
//
// The Rust cold-block bench (rust/shekyl-ffi/benches/block_connect_verify.rs)
// times a Rust PROXY for Bp+ verification; its escalation rule fired (the
// proxy landed within ~10x of the top term), so the shipped verifier —
// src/fcmp/bulletproofs_plus.cc, the inherited C++ implementation CEN-H19
// records as the largest inherited-crypto surface on the acceptance path —
// must be measured directly before any dominance conclusion, and before
// trusting the count-vs-output argmax that conditions census C2-R2's
// worst-case block model.
//
// C++-proved fixtures are sufficient subjects: verification cost is a
// function of the statement shape (padded output count), not of which prover
// emitted the proof. Cross-language acceptance parity is pinned elsewhere
// (the production path: shekyl-tx-builder proofs are what this verifier
// accepts; layout pinned by tx-builder's
// `bulletproof_oxide_layout_parses_as_wire_bpplus`).
//
// SHAPE, NOT FLOOR (rule 76): numbers print with a machine reminder; nothing
// here is a floor value. This is a gtest so it lives where C++ tests build,
// but it is an INSTRUMENT — its assertions are positive limbs (the timed
// proof must verify), not correctness coverage. R6 / CEN-H19 consumers: the
// number you need — the shipped verifier's measured cost — is this file's
// output; do not re-measure blind.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <vector>

#include "gtest/gtest.h"

#include "fcmp/bulletproofs_plus.h"
#include "fcmp/ct_ops.h"

namespace
{
  double median_us(std::vector<double> &xs)
  {
    std::sort(xs.begin(), xs.end());
    return xs[xs.size() / 2];
  }

  ct::BulletproofPlus prove_n(size_t outputs)
  {
    std::vector<uint64_t> amounts;
    ct::keyV gamma;
    for (size_t i = 0; i < outputs; ++i)
    {
      amounts.push_back(1000 + i);
      gamma.push_back(ct::skGen());
    }
    return bulletproof_plus_PROVE(amounts, gamma);
  }
} // namespace

// DISABLED_: this is a timing INSTRUMENT, not correctness coverage — the
// correctness of the shipped verifier (valid 2..9-output incl. the padded
// 16-slot circuit, aggregated, and the invalid_8/invalid_31/invalid_torsion
// negative limbs) already lives in bulletproofs_plus.cpp, so running K=21
// timing loops in every CI ctest pass would be pure noise and runtime. The
// ASSERT_TRUEs below are positive limbs FOR THE TIMING (the loop must not
// time a rejection path), not the coverage. The Pi gate script opts in via
// --gtest_also_run_disabled_tests (scripts/bench/gap7_pi4_gate.sh, cpp
// phase).
TEST(gap7_bp_bench, DISABLED_shipped_verifier_cost)
{
  static const int K = 21;

  for (const size_t outputs : {size_t(2), size_t(16)})
  {
    ct::BulletproofPlus proof = prove_n(outputs);
    // Positive limb: the proof the loop times must VERIFY, or the numbers
    // describe a rejection path.
    ASSERT_TRUE(ct::bulletproof_plus_VERIFY(proof));

    std::vector<double> us;
    us.reserve(K);
    for (int k = 0; k < K; ++k)
    {
      const auto t0 = std::chrono::steady_clock::now();
      const bool ok = ct::bulletproof_plus_VERIFY(proof);
      const auto t1 = std::chrono::steady_clock::now();
      ASSERT_TRUE(ok);
      us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
    }
    std::printf("[gap7_bp_bench] shipped single-proof VERIFY, %zu outputs: "
                "median %.1f us over %d runs (SHAPE datum — record the machine "
                "beside this number, rule 76)\n",
                outputs, median_us(us), K);
  }

  // Batched form at the Rust bench's measured zone-point argmax: 46 minimal
  // txs per 600 kB block, one 2-output proof each. The acceptance path
  // batches across a tx's proofs and the block loop batches txs, so the
  // per-proof amortized figure under batching is the number the cold-block
  // model composes with.
  {
    static const size_t N_ZONE_ARGMAX = 46;
    std::vector<ct::BulletproofPlus> proofs;
    proofs.reserve(N_ZONE_ARGMAX);
    ct::BulletproofPlus one = prove_n(2);
    for (size_t i = 0; i < N_ZONE_ARGMAX; ++i)
      proofs.push_back(one);
    ASSERT_TRUE(ct::bulletproof_plus_VERIFY(proofs));

    std::vector<double> us;
    us.reserve(K);
    for (int k = 0; k < K; ++k)
    {
      const auto t0 = std::chrono::steady_clock::now();
      const bool ok = ct::bulletproof_plus_VERIFY(proofs);
      const auto t1 = std::chrono::steady_clock::now();
      ASSERT_TRUE(ok);
      us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
    }
    const double med = median_us(us);
    std::printf("[gap7_bp_bench] shipped batched VERIFY, %zu x 2-output "
                "proofs: median %.1f us total, %.1f us/proof amortized "
                "(SHAPE datum — record the machine, rule 76)\n",
                N_ZONE_ARGMAX, med, med / N_ZONE_ARGMAX);
  }
}
