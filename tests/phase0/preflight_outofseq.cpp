// SPDX-License-Identifier: MIT
//
// LWMA-1 Phase 0 / Round 13 pre-flight harness — covers the seven §8.1
// numerical vectors against both canonical zawy12 LWMA1_() and Shekyl's
// running-max + signed-solvetime + symmetric-clamp variant.
//
// LWMA1_canonical is transcribed verbatim from zawy12/difficulty-algorithms#3
// (docs/design/refs/zawy12_issue_3_lwma1.md, lines 77-119), copyright
// (c) 2017-2018 Zawy, MIT License.
//
// LWMA1_shekyl_corrected is Shekyl Foundation original (BSD-3-Clause in
// production form), transcribed from DAA_LWMA1.md §5.3 for cross-check
// purposes. The file-level SPDX identifier MIT applies to the canonical
// function only.
//
// Round 13 motivation: Copilot review of PR #49 flagged the existing §8.1
// worked arithmetic as wrong; this harness produces the empirically-correct
// values so the doc can pin them.
//
// Also exercises the canonical and Shekyl algorithms against the other §8.1
// vectors that had u64-underflow patterns (Copilot finding 5):
//   - selfish-mine regression
//   - minimum-L floor engagement
//   - sudden 2x increase / decrease
// All vectors are re-anchored on B = 1_700_000_000 to avoid u64 underflow at
// `previous_timestamp = timestamps[0] - T` on the first iteration.

#include <cassert>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <vector>

using difficulty_type = uint64_t;

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

difficulty_type LWMA1_shekyl_corrected(std::vector<uint64_t> timestamps,
   std::vector<uint64_t> cumulative_difficulties, uint64_t T, uint64_t N, uint64_t height,
                    uint64_t FORK_HEIGHT, uint64_t difficulty_guess) {
   assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1);
   if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return difficulty_guess; }
   assert(timestamps.size() == N+1);
   __int128 L_signed = 0;
   // prev_max is __int128 (signed) to match DAA_LWMA1.md §5.4's type
   // discipline (signed 128-bit for intermediate solvetime/anchor state)
   // and to avoid the implementation-defined uint64_t->int64_t cast that
   // a 64-bit prev_max would require. The first iteration's anchor
   // `timestamps[0] - T` would underflow u64 absent §8.1's base-anchor
   // convention; the signed 128-bit form is the safe shape regardless.
   __int128 prev_max = (__int128)timestamps[0] - (__int128)T;
   for (uint64_t i = 1; i <= N; ++i) {
       __int128 solvetime = (__int128)timestamps[i] - prev_max;
       __int128 lo = -(__int128)6 * (__int128)T;
       __int128 hi =  (__int128)6 * (__int128)T;
       if (solvetime < lo) solvetime = lo;
       if (solvetime > hi) solvetime = hi;
       L_signed += (__int128)i * solvetime;
       prev_max = std::max(prev_max, (__int128)timestamps[i]);
   }
   __int128 L_min = (__int128)N * (__int128)N * (__int128)T / 20;
   if (L_signed < L_min) L_signed = L_min;
   unsigned __int128 L = (unsigned __int128)L_signed;
   uint64_t avg_D = (cumulative_difficulties[N] - cumulative_difficulties[0]) / N;
   uint64_t next_D;
   unsigned __int128 Nf = (unsigned __int128)N * (unsigned __int128)(N + 1);
   // The branching below mirrors canonical LWMA1_()'s overflow guard
   // verbatim (issue #3 lines 105-106). The threshold expression
   // `2000000ULL * N * N * T` is evaluated in uint64_t: with N=90, T=120
   // it is 1.944e12, safely below 2^64. If this harness is reused with
   // substantially larger N or T (not §8.1's parameters), the threshold
   // itself can overflow uint64_t; a future variant would need to
   // promote the comparison to unsigned __int128. For §8.1 fixtures the
   // bounded-input assumption holds.
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

static void run(const std::string& label,
                const std::vector<uint64_t>& ts,
                const std::vector<uint64_t>& cd,
                uint64_t T, uint64_t N, uint64_t height) {
    uint64_t c = LWMA1_canonical(ts, cd, T, N, height, 0, 100);
    uint64_t s = LWMA1_shekyl_corrected(ts, cd, T, N, height, 0, 100);
    std::cout << "=== " << label << " ===\n"
              << "  canonical:        " << c << "\n"
              << "  shekyl-corrected: " << s << "\n"
              << "  identical: " << (c==s ? "YES" : "NO") << "\n\n";
}

int main() {
    const uint64_t N = 90;
    const uint64_t T = 120;
    const uint64_t avg_D = 1000000;
    const uint64_t B = 1700000000ULL;  // Unix epoch base, avoids u64 underflow.

    // (1) Perfectly stable hashrate: timestamps[i] = B + i*T.
    {
        std::vector<uint64_t> ts(N+1), cd(N+1);
        for (uint64_t i = 0; i <= N; ++i) { ts[i] = B + i*T; cd[i] = i*avg_D; }
        run("(1) Perfectly stable hashrate", ts, cd, T, N, N+1);
    }

    // (2) Sudden 2x increase: timestamps[i] = B + i*(T/2).
    {
        std::vector<uint64_t> ts(N+1), cd(N+1);
        for (uint64_t i = 0; i <= N; ++i) { ts[i] = B + i*(T/2); cd[i] = i*avg_D; }
        run("(2) Sudden 2x hashrate increase (solvetime=T/2)", ts, cd, T, N, N+1);
    }

    // (3) Sudden 2x decrease: timestamps[i] = B + i*(2*T).
    {
        std::vector<uint64_t> ts(N+1), cd(N+1);
        for (uint64_t i = 0; i <= N; ++i) { ts[i] = B + i*(2*T); cd[i] = i*avg_D; }
        run("(3) Sudden 2x hashrate decrease (solvetime=2T)", ts, cd, T, N, N+1);
    }

    // (4) Solvetime clamp engagement: stable, then single +100*T jump at i=N.
    {
        std::vector<uint64_t> ts(N+1), cd(N+1);
        for (uint64_t i = 0; i <= N; ++i) { ts[i] = B + i*T; cd[i] = i*avg_D; }
        ts[N] = ts[N-1] + 100*T;  // +100T outlier (clamps to +6T)
        run("(4) Solvetime clamp engagement (last solvetime +100T, clamps to +6T)",
            ts, cd, T, N, N+1);
    }

    // (5) Minimum-L floor engagement: timestamps[i] = B + i (1s gap).
    {
        std::vector<uint64_t> ts(N+1), cd(N+1);
        for (uint64_t i = 0; i <= N; ++i) { ts[i] = B + i; cd[i] = i*avg_D; }
        run("(5) Minimum-L floor engagement (1s gap, L_raw=N*(N+1)/2)",
            ts, cd, T, N, N+1);
    }

    // (6) Out-of-sequence: stable T-spaced timestamps for i in 0..=N-1,
    //   then ts[N] is set so the LAST solvetime is -T (one period
    //   backward in time relative to ts[N-1]). The override value
    //   ts[N] = B + (N-2)*T coincides with ts[N-2] in absolute value,
    //   because ts[N-2] was assigned B + (N-2)*T by the loop — i.e.,
    //   "the last block's timestamp lands two slots earlier in the
    //   strictly-monotonic sequence." These describe the same
    //   configuration from two angles:
    //     ts[N] - ts[N-1] = (B + (N-2)*T) - (B + (N-1)*T) = -T   (solvetime axis)
    //     ts[N]           = ts[N-2]                              (absolute-value axis)
    //   Both are intended.
    {
        std::vector<uint64_t> ts(N+1), cd(N+1);
        for (uint64_t i = 0; i <= N; ++i) { ts[i] = B + i*T; cd[i] = i*avg_D; }
        ts[N] = B + (N-2)*T;  // makes solvetime[N] = -T (one period back)
        run("(6) Out-of-sequence (last solvetime = -T; ts[N] coincides with ts[N-2])",
            ts, cd, T, N, N+1);
    }

    // (7) Selfish-mine attack regression (§8.1 vector, fixed to base-anchored):
    //   timestamps[i] = B + i*T for i in 0..=N-2,
    //   timestamps[N-1] = B + (N-2)*T + 1000*T  (forward jump),
    //   timestamps[N]   = B + (N-2)*T + T       (genuine post-attack).
    {
        std::vector<uint64_t> ts(N+1), cd(N+1);
        for (uint64_t i = 0; i <= N; ++i) { ts[i] = B + i*T; cd[i] = i*avg_D; }
        ts[N-1] = B + (N-2)*T + 1000*T;
        ts[N]   = B + (N-2)*T + T;
        run("(7) Selfish-mine attack (forward jump +1000T at N-1, genuine post-attack at N)",
            ts, cd, T, N, N+1);
    }

    return 0;
}
