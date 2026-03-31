// Copyright (c) 2018-2022, The Monero Project
// Copyright (c) 2024-2026, The Shekyl Foundation

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

#include "misc_log_ex.h"
#include "syncobj.h"
#include "mlocker.h"
#include "shekyl/shekyl_secure_mem.h"

#include <atomic>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "mlocker"

static std::atomic<bool> previously_failed{ false };

namespace epee
{
  size_t mlocker::page_size = 0;
  size_t mlocker::num_locked_objects = 0;

  boost::mutex &mlocker::mutex()
  {
    static boost::mutex *vmutex = new boost::mutex();
    return *vmutex;
  }
  std::map<size_t, unsigned int> &mlocker::map()
  {
    static std::map<size_t, unsigned int> *vmap = new std::map<size_t, unsigned int>();
    return *vmap;
  }

  size_t mlocker::get_page_size()
  {
    CRITICAL_REGION_LOCAL(mutex());
    if (page_size == 0)
      page_size = shekyl_page_size();
    return page_size;
  }

  mlocker::mlocker(void *ptr, size_t len): ptr(ptr), len(len)
  {
    lock(ptr, len);
  }

  mlocker::~mlocker()
  {
    try { unlock(ptr, len); }
    catch (...) { /* ignore and do not propagate through the dtor */ }
  }

  void mlocker::lock(void *ptr, size_t len)
  {
    TRY_ENTRY();

    size_t page_size = get_page_size();
    if (page_size == 0)
      return;

    CRITICAL_REGION_LOCAL(mutex());
    const size_t first = ((uintptr_t)ptr) / page_size;
    const size_t last = (((uintptr_t)ptr) + len - 1) / page_size;
    for (size_t page = first; page <= last; ++page)
      lock_page(page);
    ++num_locked_objects;

    CATCH_ENTRY_L1("mlocker::lock", void());
  }

  void mlocker::unlock(void *ptr, size_t len)
  {
    TRY_ENTRY();

    size_t page_size = get_page_size();
    if (page_size == 0)
      return;
    CRITICAL_REGION_LOCAL(mutex());
    const size_t first = ((uintptr_t)ptr) / page_size;
    const size_t last = (((uintptr_t)ptr) + len - 1) / page_size;
    for (size_t page = first; page <= last; ++page)
      unlock_page(page);
    --num_locked_objects;

    CATCH_ENTRY_L1("mlocker::lock", void());
  }

  size_t mlocker::get_num_locked_pages()
  {
    CRITICAL_REGION_LOCAL(mutex());
    return map().size();
  }

  size_t mlocker::get_num_locked_objects()
  {
    CRITICAL_REGION_LOCAL(mutex());
    return num_locked_objects;
  }

  void mlocker::lock_page(size_t page)
  {
    std::pair<std::map<size_t, unsigned int>::iterator, bool> p = map().insert(std::make_pair(page, 1));
    if (p.second)
    {
      void *addr = (void*)(page * page_size);
      int ret = shekyl_mlock((const uint8_t*)addr, page_size);
      if (ret < 0 && !previously_failed.exchange(true))
        MERROR("Error locking page at " << addr << ", subsequent mlock errors will be silenced");
    }
    else
    {
      ++p.first->second;
    }
  }

  void mlocker::unlock_page(size_t page)
  {
    std::map<size_t, unsigned int>::iterator i = map().find(page);
    if (i == map().end())
    {
      MERROR("Attempt to unlock unlocked page at " << (void*)(page * page_size));
    }
    else
    {
      if (!--i->second)
      {
        map().erase(i);
        void *addr = (void*)(page * page_size);
        int ret = shekyl_munlock((const uint8_t*)addr, page_size);
        if (ret < 0 && !previously_failed.load())
          MERROR("Error unlocking page at " << addr);
      }
    }
  }
}
