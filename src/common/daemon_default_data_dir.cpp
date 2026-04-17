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

#include "common/daemon_default_data_dir.h"

#include <boost/filesystem/operations.hpp>

#include "common/util.h"
#include "cryptonote_config.h"

#ifdef WIN32
#  include <shlobj.h>
#  include <windows.h>
#  include <sddl.h>
#endif

namespace daemonize
{
#ifdef WIN32
  namespace
  {
    // Byte-for-byte replica of windows::check_admin from the deleted
    // src/daemonizer/windows_service.cpp. Kept private to this translation
    // unit to avoid reintroducing a separate Windows service library.
    bool check_admin_local(bool & result)
    {
      BOOL is_admin = FALSE;
      PSID p_administrators_group = nullptr;
      SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

      if (!AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &p_administrators_group))
      {
        return false;
      }

      if (!CheckTokenMembership(nullptr, p_administrators_group, &is_admin))
      {
        FreeSid(p_administrators_group);
        return false;
      }

      FreeSid(p_administrators_group);
      result = is_admin ? true : false;
      return true;
    }
  }

  boost::filesystem::path daemon_default_data_dir()
  {
    bool admin;
    if (!check_admin_local(admin))
    {
      admin = false;
    }
    // NOTE: any change to the admin/non-admin branch below is a silent data-dir
    // relocation for existing users. Non-admin Windows is impractical to pin in
    // CI; manually verify on a non-admin Windows builder before editing.
    if (admin)
    {
      return boost::filesystem::absolute(
        tools::get_special_folder_path(CSIDL_COMMON_APPDATA, true) + "\\" + CRYPTONOTE_NAME);
    }
    else
    {
      return boost::filesystem::absolute(
        tools::get_special_folder_path(CSIDL_APPDATA, true) + "\\" + CRYPTONOTE_NAME);
    }
  }
#else
  boost::filesystem::path daemon_default_data_dir()
  {
    return boost::filesystem::absolute(tools::get_default_data_dir());
  }
#endif
}
