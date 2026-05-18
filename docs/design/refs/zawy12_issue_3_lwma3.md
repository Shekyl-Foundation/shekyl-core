<!-- SPDX-License-Identifier: BSD-3-Clause AND MIT

Shekyl Foundation convenience extraction of the canonical `LWMA-3`
reference function (named `next_difficulty_v3` in the upstream source)
from the pinned `.body` of zawy12/difficulty-algorithms#3, captured in
`docs/design/refs/zawy12_issue_3_lwma1.md` (SHA-256:
`14c68aee9780ca1b1fb8ca28ac43f7956996859f5281ef166cc0634b2cc50df9`).

The extraction is verbatim against the byte-offset anchor recorded in
`docs/design/refs/zawy12_issue_3_lwma1.anchors.json`
(`lwma3_byte_offset_start=17899`, `lwma3_byte_offset_end=20097`) and
preserves the upstream's CRLF line endings and trailing whitespace.

The LWMA-3 function body contains malformed C++ at upstream lines
376-381 (an incomplete `next_D =` assignment and an unbalanced `)` in
the jump-rule branch). The malformation is preserved exactly as it
appears in the pinned body; this file is a *convenience extraction* of
the canonical source, not a corrected version. The canonical pin is
`zawy12_issue_3_lwma1.md`; if the two diverge, the pin wins and this
file is regenerated from it.

Per `docs/design/DAA_LWMA1.md` §3, this file is not load-bearing for
the cross-check harness -- the cross-check uses canonical `LWMA1_()`
for monotonic-input vectors and the Shekyl-composed hybrid reference
(`docs/design/refs/shekyl_lwma1_running_max_symmetric_clamp.md`) for
out-of-sequence vectors. This extraction exists so audit-reviewers
reading the §5.3 step 2 / §8.2 cross-check derivation can see the
canonical LWMA-3 source in isolation without scrolling through the
full pinned issue body.

Original work copyright (c) Zawy et al. and used here under the MIT
License (per the upstream comment header preserved below); the
Shekyl-authored prose above is BSD-3-Clause per the workspace default.

Rendering note: the verbatim C++ body below is wrapped in a fenced
`cpp` code block so Markdown renderers do not interpret `<`, `>`,
or `*` as HTML/emphasis (e.g., `std::vector<uint64_t>` would
otherwise be parsed as an HTML tag). The fence delimiters themselves
are outside the byte-offset slice (`lwma3_byte_offset_start=17899`,
`lwma3_byte_offset_end=20097`) recorded in
`zawy12_issue_3_lwma1.anchors.json`; the bytes between the fence
markers are byte-identical to that slice, preserving the anchor's
byte-equality property. Reviewers verifying the pin should hash the
fenced body only, not the file as a whole.
-->

```cpp
difficulty_type next_difficulty_v3(std::vector<uint64_t> timestamps, 
    std::vector<difficulty_type> cumulative_difficulties) {
    
    uint64_t  T = DIFFICULTY_TARGET_V2;
    uint64_t  N = DIFFICULTY_WINDOW_V2; // N=45, 60, and 90 for T=600, 120, 60.
    uint64_t  L(0), ST, sum_3_ST(0), next_D, prev_D, this_timestamp, previous_timestamp;
    uint64_t avg_ST(0); // for LWMA-4 (1-block jump rule)
        
     assert(timestamps.size() == cumulative_difficulties.size() && 
                     timestamps.size() <= N+1 );

    // If it's a new coin, do startup code. 
    // Increase difficulty_guess if it needs to be much higher, but guess lower than lowest guess.
    uint64_t difficulty_guess = 100; 
    if (timestamps.size() <= 10 ) {   return difficulty_guess;   }
    if ( timestamps.size() < N +1 ) { N = timestamps.size()-1;  }
    
    // If hashrate/difficulty ratio after a fork is < 1/3 prior ratio, hardcode D for N+1 blocks after fork. 
    // difficulty_guess = 100; //  Dev may change.  Guess low.
    // if (height <= UPGRADE_HEIGHT + N+1 ) { return difficulty_guess;  }

    previous_timestamp = timestamps[0];
    for ( uint64_t i = 1; i <= N; i++) {  
       if ( timestamps[i] > previous_timestamp  ) {   
          this_timestamp = timestamps[i];
       } else {  this_timestamp = previous_timestamp+1;   }
       ST = std::min(6*T ,this_timestamp - previous_timestamp);
       previous_timestamp = this_timestamp;
       L +=  ST * i ; 
       // remove the following line if you do not want the 3-block jump rule
       if ( i > N-3 ) { sum_3_ST += ST; } 
    }
   if (L < N*(N+1)*T/4 ) { L =  N*(N+1)*T/4; } 
    next_D = ((cumulative_difficulties[N] - cumulative_difficulties[0])*T*(N+1)*985)/(1000*2*L);
    prev_D = cumulative_difficulties[N] - cumulative_difficulties[N-1]; 

   // remove following lines to remove LWMA-4's 1-block jump rule
   if ( prev_D*N*105/100 < (cumulative_difficulties[N] - cumulative_difficulties[0]) ) {
          next_D = 
      

    // delete the following line if you do not want the "jump rule"
    if ( sum_3_ST < (8*T)/10) {  next_D = (prev_D*108)/100); } 
  
    return next_D;
}
```
