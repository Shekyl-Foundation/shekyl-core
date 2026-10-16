// Copyright (c) 2025-2026, The Shekyl Foundation
// Copyright (c) 2014-2024, The Monero Project
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

// The blockchain utilities' network and data-directory options. The daemon
// reads these from the Rust configuration (DAEMON_CONFIG_CUTOVER.md §2.9)
// and declares no option; the utilities keep their own option sets until
// the input grammar's Part B rules each tool (DAEMON_CONFIG_CUTOVER.md §9,
// §10). Each utility includes this header beside `common/command_line.h`.

#pragma once

#include <array>
#include <string>

#include <boost/filesystem/path.hpp>

#include "common/command_line.h"
#include "common/util.h"

namespace cryptonote
{
  inline const command_line::arg_descriptor<bool, false> arg_testnet_on  = {
    "testnet"
  , "Run on testnet. The wallet must be launched with --testnet flag."
  , false
  };
  inline const command_line::arg_descriptor<bool, false> arg_stagenet_on  = {
    "stagenet"
  , "Run on stagenet. The wallet must be launched with --stagenet flag."
  , false
  };
  inline const command_line::arg_descriptor<bool> arg_regtest_on  = {
    "regtest"
  , "Run in a regression testing mode."
  , false
  };
  // The default is the daemon's layout (`shekyl-daemon-config` `paths`): the
  // root for mainnet, and the network's own subdirectory for every other
  // network, regtest included, so a regtest utility never opens the
  // mainnet store.
  inline const command_line::arg_descriptor<std::string, false, true, 3> arg_data_dir = {
    "data-dir"
  , "Specify data directory"
  , tools::get_default_data_dir()
  , {{ &arg_testnet_on, &arg_stagenet_on, &arg_regtest_on }}
  , [](std::array<bool, 3> networks, bool defaulted, std::string val)->std::string {
      if (networks[0])
        return (boost::filesystem::path(val) / "testnet").string();
      else if (networks[1])
        return (boost::filesystem::path(val) / "stagenet").string();
      else if (networks[2])
        return (boost::filesystem::path(val) / "regtest").string();
      return val;
    }
  };
}
