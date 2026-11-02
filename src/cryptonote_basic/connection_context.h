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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
// Parts of this file are originally copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net

#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include "net/net_utils_base.h"

namespace cryptonote
{
  struct cryptonote_connection_context: public epee::net_utils::connection_context_base
  {
    cryptonote_connection_context()
      : cryptonote_connection_context(boost::uuids::uuid(), epee::net_utils::network_address(), false)
    {}

    // SSL is refused. The base is handed a constant false; the seam has
    // no SSL state to pass.
    cryptonote_connection_context(boost::uuids::uuid connection_id,
        const epee::net_utils::network_address& remote_address, bool is_income,
        std::uint8_t connector = 0xff)
      : epee::net_utils::connection_context_base(connection_id, remote_address, is_income, false, 0, 0, 0, 0, connector)
    {}

    static constexpr int handshake_command() noexcept { return 1001; }

    //! \return Payload cap for this `(command, flags)` pair, or `nullopt`
    //! if the header is unrecognised at ingress (PWD-B3a). `nullopt` is
    //! connection-fatal even for a zero-length payload — returning cap 0
    //! would admit empty unknown commands. On reject, `reject_rc` (when
    //! non-null) receives the `shekyl_levin_ingress_admit` code (`-8`
    //! unknown flags, `-9` unknown dispatch command).
    static std::optional<size_t> get_max_bytes(uint32_t command, uint32_t flags, int32_t* reject_rc = nullptr) noexcept;
  };

}
