// SPDX-License-Identifier: MIT
//
// LWMA-1 Phase 0 pre-flight harness — canonical-only run against the
// DAA_LWMA1.md §8.1 stable hashrate vector.
//
// The LWMA1_() function below is transcribed verbatim from the pinned
// .body of zawy12/difficulty-algorithms#3
// (docs/design/refs/zawy12_issue_3_lwma1.md, lines 77-119) and is
// copyright (c) 2017-2018 Zawy, used here under the MIT License.
//
// The harness wrapper (main(), inputs, and output formatting) is
// Shekyl Foundation original; the MIT identifier above covers the
// canonical function. The Shekyl wrapper is otherwise compatible with
// the project's BSD-3-Clause production code.
//
// Canonical reference: https://github.com/zawy12/difficulty-algorithms/issues/3
// LWMA1_() function transcribed verbatim from the pinned raw .body
// (docs/design/refs/zawy12_issue_3_lwma1.md), lines 77-119.
//
// Inputs (§8.1 "perfectly stable hashrate" vector):
//   N = 90, T = 120
//   timestamps[i] = i * T for i in 0..=N   (strictly monotonic, delta=T)
//   cumulative_difficulties[i] = i * 1_000_000 for i in 0..=N (avg_D = 1_000_000)
//   FORK_HEIGHT = 0, height = N+1
//   difficulty_guess = 100
//
// Expected (per design doc §8.1 analytical derivation): 990_000.
// This harness records the canonical's actual output for §8.1 calibration.

#include <cassert>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <vector>

using difficulty_type = uint64_t;

// Verbatim transcription of canonical LWMA1_() from issue #3 lines 77-119
// (docs/design/refs/zawy12_issue_3_lwma1.md). MIT License, (c) 2017-2018 Zawy.
difficulty_type LWMA1_(std::vector<uint64_t> timestamps,
   std::vector<uint64_t> cumulative_difficulties, uint64_t T, uint64_t N, uint64_t height,
                    uint64_t FORK_HEIGHT, uint64_t  difficulty_guess) {

   assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1 );

   if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return difficulty_guess; }
   assert(timestamps.size() == N+1);

   uint64_t  L(0), next_D, i, this_timestamp(0), previous_timestamp(0), avg_D;

    previous_timestamp = timestamps[0]-T;
    for ( i = 1; i <= N; i++) {
        if ( timestamps[i]  > previous_timestamp ) {   this_timestamp = timestamps[i];  }
        else {  this_timestamp = previous_timestamp+1;   }
        L +=  i*std::min(6*T ,this_timestamp - previous_timestamp);
        previous_timestamp = this_timestamp;
    }
    if (L < N*N*T/20 ) { L =  N*N*T/20; }
    avg_D = ( cumulative_difficulties[N] - cumulative_difficulties[0] )/ N;

    if (avg_D > 2000000*N*N*T) {
        next_D = (avg_D/(200*L))*(N*(N+1)*T*99);
    }
    else {    next_D = (avg_D*N*(N+1)*T*99)/(200*L);    }

    i = 1000000000;
    while (i > 1) {
        if ( next_D > i*100 ) { next_D = ((next_D+i/2)/i)*i; break; }
        else { i /= 10; }
    }
    return  next_D;
}

int main() {
    const uint64_t N = 90;
    const uint64_t T = 120;
    const uint64_t avg_D = 1000000;

    std::vector<uint64_t> timestamps(N+1);
    std::vector<uint64_t> cumulative_difficulties(N+1);
    for (uint64_t i = 0; i <= N; ++i) {
        timestamps[i] = 1700000000ULL + i * T;
        cumulative_difficulties[i] = i * avg_D;
    }

    uint64_t out = LWMA1_(timestamps, cumulative_difficulties, T, N, /*height=*/N+1,
                         /*FORK_HEIGHT=*/0, /*difficulty_guess=*/100);

    std::cout << "Phase 1 pre-flight verification result:" << std::endl;
    std::cout << "  Inputs: N=" << N << ", T=" << T << ", avg_D=" << avg_D << std::endl;
    std::cout << "  Stable monotonic timestamps[i] = i*T, cumulative_difficulties[i] = i*avg_D" << std::endl;
    std::cout << "  Canonical LWMA1_() output: " << out << std::endl;
    std::cout << "  Design doc §8.1 expected: 990000" << std::endl;
    std::cout << "  Match: " << (out == 990000 ? "YES" : "NO") << std::endl;
    return 0;
}
