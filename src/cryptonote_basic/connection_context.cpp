// Copyright (c) 2020-2022, The Monero Project

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

#include "connection_context.h"

#include <limits>
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{
  std::optional<std::size_t> cryptonote_connection_context::get_max_bytes(const int command, const uint32_t flags) noexcept
  {
    // PWD-B3 / PWD-B3a / PWD-B4: the table and the discriminator live in
    // rust/shekyl-levin. This is the marshaling shim (rule 20). PWD-B6
    // still owns deleting NOTIFY_NEW_BLOCK (2001 stays in the table);
    // PWD-B10 still owns deleting COMMAND_PING from the protocol defs
    // (already absent from the cap table).
    uint64_t cap = 0;
    const int32_t rc = shekyl_levin_ingress_admit(
        static_cast<uint32_t>(command), flags, &cap);
    if (rc != 0)
      return std::nullopt;
    if (cap >= std::numeric_limits<size_t>::max())
      return std::numeric_limits<size_t>::max();
    return static_cast<size_t>(cap);
  }

  void cryptonote_connection_context::set_state_normal()
  {
    m_state = state_normal;
    m_expected_heights_start = 0;
    m_needed_objects.clear();
    m_needed_objects.shrink_to_fit();
    m_expected_heights.clear();
    m_expected_heights.shrink_to_fit();
    m_requested_objects.clear();
  }

  std::optional<crypto::hash> cryptonote_connection_context::get_expected_hash(const uint64_t height) const
  {
    const auto difference = height - m_expected_heights_start;
    if (height < m_expected_heights_start || m_expected_heights.size() <= difference)
      return std::nullopt;
    return m_expected_heights[difference];
  }
} // cryptonote
