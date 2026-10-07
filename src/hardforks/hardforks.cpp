// Copyright (c) 2014-2022, The Monero Project
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

#include "hardforks.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "blockchain.hardforks"

// Rebooted chain: all features active from genesis.
// One schedule for every issued network. Fields are version, height, time.
// The height is the CEN-F21 epoch. The time is the CryptoNote-era stamp
// RC-162 records; acceptance does not read it.
const hardfork_t hard_fork_schedule[] = {
  { 1, 1, 1341378000 },
};
const size_t num_hard_fork_schedule = sizeof(hard_fork_schedule) / sizeof(hard_fork_schedule[0]);

std::pair<uint8_t, uint64_t> regtest_hard_fork_row()
{
  const hardfork_t &newest = hard_fork_schedule[num_hard_fork_schedule - 1];
  return {newest.version, hard_fork_schedule[0].height};
}
