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

#include <boost/algorithm/string/find_iterator.hpp>
#include <boost/algorithm/string/finder.hpp>
#include <boost/chrono/duration.hpp>
#include <boost/endian/conversion.hpp>
#include <optional>
#include <boost/thread/future.hpp>
#include <boost/utility/string_ref.hpp>
#include <chrono>
#include <cstring>
#include <utility>

#include "common/command_line.h"
#include "cryptonote_core/cryptonote_core.h"
#include "shekyl/shekyl_ffi.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "net_node.h"
#include "net/net_utils_base.h"
#include "net/socks.h"
#include "net/parse.h"
#include "net/tor_address.h"
#include "p2p/p2p_protocol_defs.h"
#include "string_tools.h"
#include "string_tools_lexical.h"

namespace nodetool
{
    // PWD-E7 (P2P_2_ENDPOINT_ROUND.md): the durable-address warning is stated
    // wherever this flag is documented, because the failure mode is quiet --
    // this flag is not a custody preference; taking it is opting into a
    // durable address. The default posture (no flag) is an ephemeral per-boot
    // onion the daemon publishes itself; see arg_no_ephemeral_tor below.
    const command_line::arg_descriptor<bool> arg_no_sync = {"no-sync", "Don't synchronize the blockchain with other peers", false};

    const command_line::arg_descriptor<bool> arg_pad_transactions = {
      "pad-transactions", "Pad relayed transactions to help defend against traffic volume analysis", false
    };


}
