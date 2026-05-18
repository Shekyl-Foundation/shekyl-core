// SPDX-License-Identifier: MIT
//
// Verify Shekyl's corrected pseudocode (subtract-then-update running max)
// produces byte-identical output to canonical LWMA1_() on monotonic input
// and diverges (Shekyl > canonical) on out-of-sequence input.
//
// LWMA1_canonical is transcribed verbatim from zawy12/difficulty-algorithms#3
// (docs/design/refs/zawy12_issue_3_lwma1.md, lines 77-119), copyright
// (c) 2017-2018 Zawy, MIT License.
//
// LWMA1_shekyl_corrected is Shekyl Foundation original, transcribed from
// the textual specification in DAA_LWMA1.md §5.3, expressed in C++ for
// cross-check purposes. The Shekyl variant is otherwise compatible with
// BSD-3-Clause; the file-level SPDX identifier MIT applies to the
// canonical function only.

#include <cassert>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <vector>

using difficulty_type = uint64_t;

// Canonical LWMA1_() verbatim from issue #3.
difficulty_type LWMA1_canonical(std::vector<uint64_t> timestamps,
   std::vector<uint64_t> cumulative_difficulties, uint64_t T, uint64_t N, uint64_t height,
                    uint64_t FORK_HEIGHT, uint64_t difficulty_guess) {
   assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1 );
   if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return difficulty_guess; }
   assert(timestamps.size() == N+1);
   uint64_t L(0), next_D, i, this_timestamp(0), previous_timestamp(0), avg_D;
   previous_timestamp = timestamps[0]-T;
   for ( i = 1; i <= N; i++) {
       if ( timestamps[i]  > previous_timestamp ) {   this_timestamp = timestamps[i];  }
       else {  this_timestamp = previous_timestamp+1;   }
       L +=  i*std::min(6*T ,this_timestamp - previous_timestamp);
       previous_timestamp = this_timestamp;
   }
   if (L < N*N*T/20 ) { L =  N*N*T/20; }
   avg_D = ( cumulative_difficulties[N] - cumulative_difficulties[0] )/ N;
   if (avg_D > 2000000*N*N*T) { next_D = (avg_D/(200*L))*(N*(N+1)*T*99); }
   else { next_D = (avg_D*N*(N+1)*T*99)/(200*L); }
   i = 1000000000;
   while (i > 1) {
       if ( next_D > i*100 ) { next_D = ((next_D+i/2)/i)*i; break; }
       else { i /= 10; }
   }
   return  next_D;
}

// Shekyl's corrected pseudocode: subtract-then-max, signed solvetime, symmetric ±6T clamp.
difficulty_type LWMA1_shekyl_corrected(std::vector<uint64_t> timestamps,
   std::vector<uint64_t> cumulative_difficulties, uint64_t T, uint64_t N, uint64_t height,
                    uint64_t FORK_HEIGHT, uint64_t difficulty_guess) {
   assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1);
   if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return difficulty_guess; }
   assert(timestamps.size() == N+1);

   __int128 L_signed = 0;
   int64_t prev_max = (int64_t)timestamps[0] - (int64_t)T;
   for (uint64_t i = 1; i <= N; ++i) {
       __int128 solvetime = (__int128)timestamps[i] - (__int128)prev_max;
       __int128 lo = -(__int128)6 * (__int128)T;
       __int128 hi =  (__int128)6 * (__int128)T;
       if (solvetime < lo) solvetime = lo;
       if (solvetime > hi) solvetime = hi;
       L_signed += (__int128)i * solvetime;
       prev_max = std::max(prev_max, (int64_t)timestamps[i]);
   }
   __int128 L_min = (__int128)N * (__int128)N * (__int128)T / 20;
   if (L_signed < L_min) L_signed = L_min;
   unsigned __int128 L = (unsigned __int128)L_signed;
   uint64_t avg_D = (cumulative_difficulties[N] - cumulative_difficulties[0]) / N;
   uint64_t next_D;
   unsigned __int128 Nf = (unsigned __int128)N * (unsigned __int128)(N + 1);
   if (avg_D > 2000000ULL * N * N * T) {
       next_D = (uint64_t)(((unsigned __int128)avg_D / (200ULL * L)) * (Nf * T * 99ULL));
   } else {
       next_D = (uint64_t)(((unsigned __int128)avg_D * Nf * T * 99ULL) / (200ULL * L));
   }
   uint64_t r = 1000000000ULL;
   while (r > 1) {
       if (next_D > r * 100ULL) { next_D = ((next_D + r/2ULL) / r) * r; break; }
       else { r /= 10ULL; }
   }
   return next_D;
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

    uint64_t out_canon = LWMA1_canonical(timestamps, cumulative_difficulties, T, N, N+1, 0, 100);
    uint64_t out_shekyl = LWMA1_shekyl_corrected(timestamps, cumulative_difficulties, T, N, N+1, 0, 100);

    std::cout << "Stable monotonic (timestamps[i] = 1.7e9 + i*T, avg_D=1_000_000):" << std::endl;
    std::cout << "  Canonical LWMA1_() output: " << out_canon << std::endl;
    std::cout << "  Shekyl corrected output:   " << out_shekyl << std::endl;
    std::cout << "  Byte-identical: " << (out_canon == out_shekyl ? "YES" : "NO") << std::endl;

    // Out-of-sequence test vector: t2 < t1.
    std::vector<uint64_t> ts_oos(N+1);
    for (uint64_t i = 0; i <= N; ++i) ts_oos[i] = 1700000000ULL + i * T;
    ts_oos[2] = ts_oos[1] - 5*T;  // out-of-sequence: t2 = t1 - 30
    uint64_t out_canon_oos = LWMA1_canonical(ts_oos, cumulative_difficulties, T, N, N+1, 0, 100);
    uint64_t out_shekyl_oos = LWMA1_shekyl_corrected(ts_oos, cumulative_difficulties, T, N, N+1, 0, 100);
    std::cout << "\nOut-of-sequence (t2 = t1 - 30, attacker tries to inflate solvetime[3]):" << std::endl;
    std::cout << "  Canonical LWMA1_() output: " << out_canon_oos << std::endl;
    std::cout << "  Shekyl corrected output:   " << out_shekyl_oos << std::endl;
    std::cout << "  Diverge (expected): " << (out_canon_oos != out_shekyl_oos ? "YES" : "NO") << std::endl;
    return 0;
}
