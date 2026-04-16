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

#pragma once

#include <boost/filesystem/path.hpp>

namespace daemonize
{
  // Returns the default data directory for the daemon.
  //
  // POSIX: boost::filesystem::absolute(tools::get_default_data_dir()), i.e.
  //        $HOME/.shekyl (or /etc/shekyl on non-root login with no $HOME).
  //
  // Windows: admin → CSIDL_COMMON_APPDATA\shekyl  (typically C:\ProgramData\shekyl)
  //          non-admin → CSIDL_APPDATA\shekyl    (typically C:\Users\<user>\AppData\Roaming\shekyl)
  //
  // This preserves the exact byte-for-byte behavior of the old
  // daemonizer::get_default_data_dir() across the daemonizer removal.
  // tools::get_default_data_dir() alone is insufficient on Windows because
  // it always returns CSIDL_COMMON_APPDATA, which would silently relocate
  // non-admin user data.
  boost::filesystem::path daemon_default_data_dir();
}
