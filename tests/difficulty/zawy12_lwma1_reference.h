// SPDX-License-Identifier: MIT
//
// Adapted verbatim from zawy12/difficulty-algorithms Issue #3
// (LWMA-1 canonical reference) at the revision pinned in
// docs/design/refs/zawy12_issue_3_lwma1.md
// (SHA-256: 14c68aee9780ca1b1fb8ca28ac43f7956996859f5281ef166cc0634b2cc50df9,
//  captured 2026-05-18T05:25:21Z).
//
// The byte-offset anchor for `LWMA1_()` within the pinned `.body` is
// recorded in docs/design/refs/zawy12_issue_3_lwma1.anchors.json
// (`lwma1_byte_offset_start=5953`, `lwma1_byte_offset_end=7803`); the
// function body below is the contents of that byte range, modulo CRLF
// → LF line-ending normalization for in-tree readability and the
// addition of the `difficulty_type` typedef shim immediately below
// (canonical zawy12 sources expect the consuming project to provide
// the typedef; Shekyl's cross-check harness defines it as uint64_t to
// match the canonical zawy12 LWMA-1 width). No other modifications.
//
// Original work copyright (c) Zawy et al. and used here under the MIT
// License (per the LICENSE file at
// https://github.com/zawy12/difficulty-algorithms/blob/master/LICENSE).
//
// This file is consumed by tests/difficulty/lwma1_cross_check.cpp as
// the canonical-LWMA-1 byte-equality reference for the §8.1 monotonic-
// timestamp vectors of docs/design/DAA_LWMA1.md. For the out-of-sequence
// vectors (§8.1 vectors 6 and 7), see
// tests/difficulty/shekyl_lwma1_hybrid_reference.h instead -- canonical
// LWMA-1 deliberately differs from Shekyl's running-max + symmetric-
// clamp refinement on those inputs (the divergence is the load-bearing
// security property per zawy12 issue #24 item 14).

#pragma once

#include <cassert>
#include <cstdint>
#include <algorithm>
#include <vector>

namespace shekyl_test::zawy12_canonical {

// Canonical zawy12 LWMA-1 uses uint64_t for difficulty_type; the
// consuming project provides the typedef. Shekyl's wider u128
// difficulty (DAA_LWMA1.md §6.1) is checked against the canonical
// width by asserting `hi == 0` and `lo == canonical` at the cross-
// check call site.
using difficulty_type = uint64_t;

// Begin verbatim canonical LWMA-1 (zawy12 issue #3 LWMA-1 reference,
// pinned .body byte range [5953, 7803)). Whitespace and indentation
// preserved as in upstream.

difficulty_type LWMA1_(std::vector<uint64_t> timestamps,
   std::vector<uint64_t> cumulative_difficulties, uint64_t T, uint64_t N, uint64_t height,
					uint64_t FORK_HEIGHT, uint64_t  difficulty_guess) {

   // This old way was not very proper
   // uint64_t  T = DIFFICULTY_TARGET;
   // uint64_t  N = DIFFICULTY_WINDOW; // N=60, 90, and 150 for T=600, 120, 60.

   // Genesis should be the only time sizes are < N+1.
   assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1 );

   // Hard code D if there are not at least N+1 BLOCKS after fork (or genesis)
   // This helps a lot in preventing a very common problem in CN forks from conflicting difficulties.
   if (height >= FORK_HEIGHT && height < FORK_HEIGHT + N) { return difficulty_guess; }
   assert(timestamps.size() == N+1);

   uint64_t  L(0), next_D, i, this_timestamp(0), previous_timestamp(0), avg_D;

	previous_timestamp = timestamps[0]-T;
	for ( i = 1; i <= N; i++) {
		// Safely prevent out-of-sequence timestamps
		if ( timestamps[i]  > previous_timestamp ) {   this_timestamp = timestamps[i];  }
		else {  this_timestamp = previous_timestamp+1;   }
		L +=  i*std::min(6*T ,this_timestamp - previous_timestamp);
		previous_timestamp = this_timestamp;
	}
	if (L < N*N*T/20 ) { L =  N*N*T/20; }
	avg_D = ( cumulative_difficulties[N] - cumulative_difficulties[0] )/ N;

	// Prevent round off error for small D and overflow for large D.
	if (avg_D > 2000000*N*N*T) {
		next_D = (avg_D/(200*L))*(N*(N+1)*T*99);
	}
	else {    next_D = (avg_D*N*(N+1)*T*99)/(200*L);    }

	// Optional. Make all insignificant digits zero for easy reading.
	i = 1000000000;
	while (i > 1) {
		if ( next_D > i*100 ) { next_D = ((next_D+i/2)/i)*i; break; }
		else { i /= 10; }
	}
	return  next_D;
}

// End verbatim canonical LWMA-1.

} // namespace shekyl_test::zawy12_canonical
