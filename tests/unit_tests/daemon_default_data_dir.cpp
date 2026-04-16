// Copyright (c) 2018-2026, The Shekyl Foundation
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

// Pinning test for daemonize::daemon_default_data_dir().
//
// Purpose: guard against silent data-directory drift after the daemonizer
// removal (V3.1). The old daemonizer::get_default_data_dir() and the new
// daemonize::daemon_default_data_dir() must resolve to bit-identical paths
// on every platform — any drift on Windows, specifically, would relocate
// existing users' wallet and chain data to a new directory without warning.
//
// This test pins the resolved path against its expected construction on the
// platforms CI exercises:
//   POSIX: boost::filesystem::absolute(tools::get_default_data_dir())
//   Windows (non-admin CI): absolute(CSIDL_APPDATA + "\\" + CRYPTONOTE_NAME)
// The admin-Windows branch is impractical to run in CI; it is covered by
// the daemon_default_data_dir.cpp code-path comment and a one-shot manual
// check on a non-admin Windows builder prior to release.

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>

#include "common/daemon_default_data_dir.h"
#include "common/util.h"
#include "cryptonote_config.h"

#ifdef WIN32
#  include <shlobj.h>
#  include <windows.h>
#endif

TEST(daemon_default_data_dir, matches_platform_expected_path)
{
#ifdef WIN32
  // CI runs unelevated; assert the CSIDL_APPDATA branch bit-for-bit.
  boost::filesystem::path const expected = boost::filesystem::absolute(
      tools::get_special_folder_path(CSIDL_APPDATA, true) + "\\" + CRYPTONOTE_NAME);
#else
  boost::filesystem::path const expected = boost::filesystem::absolute(
      tools::get_default_data_dir());
#endif

  EXPECT_EQ(expected, daemonize::daemon_default_data_dir());
}

TEST(daemon_default_data_dir, path_is_absolute)
{
  EXPECT_TRUE(daemonize::daemon_default_data_dir().is_absolute());
}
