// Copyright (c) 2025-2026, The Shekyl Foundation
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
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <cstdint>

namespace shekyl {

// The transaction-volume operand as the exact window it is (FL-R24).
//
// Until FL-R24 the daemon reduced the trailing SHEKYL_TX_VOLUME_WINDOW
// (720) blocks to ONE integer -- `tx_count_sum / blocks`, truncating -- and
// passed that across the FFI as `tx_volume_avg`. The truncation was a
// quantizer on a consensus operand: a tick of it moves the release
// multiplier by 1/V, and the block reward and the served fee floor with it
// (FEE_LADDER_DERIVATION.md §11.7, FL-E1: the integer arm holds the fee
// loop in a limit cycle the exact arm does not have).
//
// This struct is the marshal shape that replaces the scalar: C++ counts,
// Rust divides. `blocks` is the number of blocks the window actually covers
// (720 once the chain is that deep, `height` before it, 0 at genesis) and
// the Rust `TxVolume` forms `tx_count_sum / (baseline * blocks)` in one
// division. No C++ code divides these two fields; a site that wants the
// ratio passes both through the FFI.
struct tx_volume_window
{
  uint64_t tx_count_sum = 0;
  uint64_t blocks = 0;
};

} // namespace shekyl
