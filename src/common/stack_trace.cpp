// Copyright (c) 2025-2026, The Shekyl Foundation
// Copyright (c) 2016-2022, The Monero Project
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

// The previous implementation relied on easylogging++'s
// `ELPP_FEATURE_CRASH_LOG` path (`el::base::debug::StackTrace`) for
// targets where libunwind wasn't in play (GCC-Linux, MSVC, MinGW,
// Android). The vendored tree is gone. We now key the libunwind
// walker entirely off the CMake-provided `HAVE_LIBUNWIND` macro
// (see the `find_package(Libunwind)` block in the root
// `CMakeLists.txt`): when it's defined we call `unw_*`, otherwise
// `log_stack_trace` emits a placeholder line so the build still
// links and crash-handler smoke tests keep exercising the
// `__cxa_throw` hook. A dedicated Rust unwind-helper crate is the
// scheduled follow-up.
#if defined(HAVE_LIBUNWIND)
#define USE_UNWIND
#endif

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <cxxabi.h>
#ifdef USE_UNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif
// `common/compat.h` provides the POSIX `<dlfcn.h>` (gated on
// `!STATICLIB && !_WIN32`) that `__cxa_throw` wrapping needs for
// `dlsym(RTLD_NEXT, ...)`; routing through it keeps the lint rule
// in `.github/workflows/build.yml` ("reject direct POSIX-header
// includes in src/") happy.
#include "common/compat.h"
#include "common/stack_trace.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_log.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "stacktrace"

// Stack traces predate the logging subsystem — the very reason we
// capture them is because something went catastrophically wrong
// (typically an uncaught exception or an abort). `ST_LOG` therefore
// emits directly through the FFI without going through the
// `stringstream`-wrapping `MCLOG_TYPE` macro: if
// `shekyl_log_level_enabled` answers false (logger not yet
// initialized, or the category filter excludes it) we fall through
// to `std::cerr` so the crash information is never silently lost.
#define ST_LOG(x) \
  do { \
    std::stringstream _st_ss; \
    _st_ss << x; \
    const std::string _st_msg = _st_ss.str(); \
    const char *const _st_cat = SHEKYL_DEFAULT_LOG_CATEGORY; \
    const std::size_t _st_cat_len = std::strlen(_st_cat); \
    if (::shekyl_log_level_enabled(SHEKYL_LOG_LEVEL_INFO, _st_cat, _st_cat_len)) { \
      ::shekyl_log_emit( \
        SHEKYL_LOG_LEVEL_INFO, \
        _st_cat, _st_cat_len, \
        __FILE__, std::strlen(__FILE__), \
        static_cast<std::uint32_t>(__LINE__), \
        ELPP_FUNC, std::strlen(ELPP_FUNC), \
        _st_msg.data(), _st_msg.size()); \
    } else { \
      std::cerr << _st_msg << std::endl; \
    } \
  } while (0)

// from https://stackoverflow.com/questions/11665829/how-can-i-print-stack-trace-for-caught-exceptions-in-c-code-injection-in-c

// The decl of __cxa_throw in /usr/include/.../cxxabi.h uses
// 'std::type_info *', but GCC's built-in protype uses 'void *'.
#ifdef __clang__
#define CXA_THROW_INFO_T std::type_info
#else // !__clang__
#define CXA_THROW_INFO_T void
#endif // !__clang__

#if defined(_MSC_VER)
#define NORETURN_ATTR __declspec(noreturn)
#else
#define NORETURN_ATTR __attribute__((noreturn))
#endif

#ifdef STATICLIB
#define CXA_THROW __wrap___cxa_throw
extern "C"
NORETURN_ATTR
void __real___cxa_throw(void *ex, CXA_THROW_INFO_T *info, void (*dest)(void*));
#else // !STATICLIB
#define CXA_THROW __cxa_throw
extern "C"
typedef
#ifdef __clang__ // only clang, not GCC, lets apply the attr in typedef
NORETURN_ATTR
#endif // __clang__
void (cxa_throw_t)(void *ex, CXA_THROW_INFO_T *info, void (*dest)(void*));
#endif // !STATICLIB

extern "C"
NORETURN_ATTR
void CXA_THROW(void *ex, CXA_THROW_INFO_T *info, void (*dest)(void*))
{

  int status;
  char *dsym = abi::__cxa_demangle(((const std::type_info*)info)->name(), NULL, NULL, &status);
  tools::log_stack_trace((std::string("Exception: ")+((!status && dsym) ? dsym : (const char*)info)).c_str());
  free(dsym);

#ifndef STATICLIB
#ifndef __clang__ // for GCC the attr can't be applied in typedef like for clang
#ifndef _MSC_VER
  __attribute__((noreturn))
#endif
#endif // !__clang__
   cxa_throw_t *__real___cxa_throw = (cxa_throw_t*)dlsym(RTLD_NEXT, "__cxa_throw");
#endif // !STATICLIB
  __real___cxa_throw(ex, info, dest);
}

namespace tools
{

void log_stack_trace(const char *msg)
{
#ifdef USE_UNWIND
  unw_context_t ctx;
  unw_cursor_t cur;
  unw_word_t ip, off;
  unsigned level;
  char sym[512], *dsym;
  int status;
#endif

  if (msg)
    ST_LOG(msg);
  ST_LOG("Unwound call stack:");

#ifdef USE_UNWIND
  if (unw_getcontext(&ctx) < 0) {
    ST_LOG("Failed to create unwind context");
    return;
  }
  if (unw_init_local(&cur, &ctx) < 0) {
    ST_LOG("Failed to find the first unwind frame");
    return;
  }
  for (level = 1; level < 999; ++level) { // 999 for safety
    int ret = unw_step(&cur);
    if (ret < 0) {
      ST_LOG("Failed to find the next frame");
      return;
    }
    if (ret == 0)
      break;
    if (unw_get_reg(&cur, UNW_REG_IP, &ip) < 0) {
      ST_LOG("  " << std::setw(4) << level);
      continue;
    }
    if (unw_get_proc_name(&cur, sym, sizeof(sym), &off) < 0) {
      ST_LOG("  " << std::setw(4) << level << std::setbase(16) << std::setw(20) << "0x" << ip);
      continue;
    }
    dsym = abi::__cxa_demangle(sym, NULL, NULL, &status);
    ST_LOG("  " << std::setw(4) << level << std::setbase(16) << std::setw(20) << "0x" << ip << " " << (!status && dsym ? dsym : sym) << " + " << "0x" << off);
    free(dsym);
  }
#else
  // Non-libunwind targets (MSVC / MinGW / Android) no longer have
  // the vendored easylogging++ stack walker. Emit a placeholder so
  // operators and crash-handler smoke tests still see the
  // `log_stack_trace` call site in the stream; the dedicated Rust
  // unwind-helper crate fills this in.
  ST_LOG("  <stack trace capture not implemented on this target>");
#endif
}

}  // namespace tools
