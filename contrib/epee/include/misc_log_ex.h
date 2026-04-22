// Copyright (c) 2025-2026, The Shekyl Foundation
// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#ifndef _MISC_LOG_EX_H_
#define _MISC_LOG_EX_H_

#include "shekyl/shekyl_log.h"

#ifdef __cplusplus

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
// The retired `easylogging++.h` transitively supplied `<memory>`,
// `<vector>`, `<algorithm>`, `<functional>`, and `<chrono>` to every TU
// that reached it through misc_log_ex.h. Several production sources
// (e.g. `contrib/epee/src/wipeable_string.cpp`) relied on that leakage
// without explicit includes of their own; we preserve the contract here
// to keep the migration bisection-safe instead of fanning out per-file
// patch-ups across the codebase.
#include <algorithm>
#include <chrono>
#include <fstream>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// easylogging++ compatibility shim
// ---------------------------------------------------------------------------
//
// The M*/MC* logging macros historically accepted `el::Level`, `el::Color`,
// and `el::base::DispatchAction` arguments — see the 1,345 call sites that
// pre-date the tracing migration. Rather than touch every call site, we
// keep the `el::` namespace alive as a thin shim whose Level values match
// the `SHEKYL_LOG_LEVEL_*` numeric contract in shekyl/shekyl_log.h. Colors
// and dispatch actions are accepted and ignored — the Rust subscriber
// handles ANSI coloring for the stderr sink and file persistence itself.
//
// The shim is *disabled* when the TU has already pulled in the real
// easylogging++ header (i.e. the EASYLOGGINGPP_H guard is defined). That
// escape hatch is used exclusively by `contrib/epee/src/mlog.cpp` during
// the multi-commit C++ shim integration, and will go away once mlog.cpp
// has been converted end-to-end in the follow-up `mlog-cpp` commit.
//
// Note on ODR: only types that do NOT also exist in easylogging++ (the
// `el::detail::ElppShim` / `VRegistryShim` helpers that back the `ELPP`
// macro) live in this shim. We deliberately do NOT redefine
// `el::base::Writer`, `el::LevelHelper`, or `CINFO` here — those names
// overlap with easylogging++'s own definitions and a link step that
// mixes compat-mode and real-mode TUs merges the two versions into a
// single symbol with mismatched layouts (observed: `munmap_chunk():
// invalid pointer` during `mlog_set_categories` teardown). Direct users
// of `el::base::Writer` in production code — perf_timer.cpp,
// stack_trace.cpp, cryptonote_protocol_handler.inl — are edited to
// route through `shekyl_log_emit` directly instead.
#ifndef EASYLOGGINGPP_H

namespace el
{
  enum class Level : std::uint8_t
  {
    Fatal   = SHEKYL_LOG_LEVEL_FATAL,
    Error   = SHEKYL_LOG_LEVEL_ERROR,
    Warning = SHEKYL_LOG_LEVEL_WARNING,
    Info    = SHEKYL_LOG_LEVEL_INFO,
    Debug   = SHEKYL_LOG_LEVEL_DEBUG,
    Trace   = SHEKYL_LOG_LEVEL_TRACE,
  };

  enum class Color : std::uint8_t
  {
    Default = 0,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
  };

  namespace base
  {
    enum class DispatchAction : std::uint8_t
    {
      NormalLog = 0,
      FileOnlyLog,
    };
  }

  namespace detail
  {
    /// Shim routed by the legacy `ELPP->vRegistry()->allowed(level, cat)`
    /// call pattern — still used by db_lmdb.cpp, transport.cpp,
    /// cryptonote_protocol_handler.inl, and perf_timer.cpp after the
    /// tracing cut-over. The underlying gate is the same
    /// `shekyl_log_level_enabled` FFI call that `MCLOG_TYPE` uses, so both
    /// code paths honor the identical filter.
    struct VRegistryShim
    {
      inline bool allowed(Level level, const char* category) const noexcept
      {
        const char* c = category ? category : "";
        return shekyl_log_level_enabled(
          static_cast<std::uint8_t>(level), c, std::strlen(c));
      }
    };

    struct ElppShim
    {
      inline VRegistryShim* vRegistry() const noexcept
      {
        static VRegistryShim v;
        return &v;
      }
    };

    inline ElppShim* elpp_ptr() noexcept
    {
      static ElppShim e;
      return &e;
    }
  } // namespace detail
} // namespace el

#define ELPP (::el::detail::elpp_ptr())

#endif // !EASYLOGGINGPP_H

// ---------------------------------------------------------------------------
// Function-name sentinel — historically supplied by easylogging++.
// ---------------------------------------------------------------------------
#ifndef ELPP_FUNC
# if defined(_MSC_VER)
#   define ELPP_FUNC __FUNCSIG__
# elif defined(__GNUC__) || defined(__clang__)
#   define ELPP_FUNC __PRETTY_FUNCTION__
# else
#   define ELPP_FUNC __func__
# endif
#endif

// Declares an `operator<<(std::ostream&, const ClassType&)` overload so
// `<< connection_context` etc. keep routing through `MGINFO` / `MERROR`
// stringification. Historically supplied by easylogging++'s public API
// (which aliased `el::base::type::ostream_t` to `std::ostream` in the
// non-unicode build), preserved here so existing ADL lookup continues
// to bind to the `std::ostream&` overload.
#ifndef MAKE_LOGGABLE
#define MAKE_LOGGABLE(ClassType, ClassInstance, OutputStreamInstance) \
  std::ostream& operator<<(std::ostream& OutputStreamInstance, const ClassType& ClassInstance)
#endif

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "default"

#define MAX_LOG_FILE_SIZE 104850000 // 100 MB - 7600 bytes
#define MAX_LOG_FILES 50

#define LOG_TO_STRING(x) \
    std::stringstream ss; \
    ss << x; \
    const std::string str = ss.str();

// ---------------------------------------------------------------------------
// MCLOG_TYPE: single C++ entry point for every M*/MC* macro. The body gates
// on `shekyl_log_level_enabled` *before* constructing the stringstream so
// disabled events never pay the formatting cost, then emits through the
// Rust FFI. The `color` and `type` parameters are intentionally consumed
// and discarded — the subscriber owns colorization and file routing.
//
// `(cat)` is evaluated exactly once and collapsed to a non-null
// `_shekyl_cat_str` / `_shekyl_cat_len` pair before either FFI call, so
// the hot path (gate returns true) pays a single `strlen` and the cold
// path (gate returns false) pays zero. The null/empty normalization
// matches the FFI's documented contract: passing `(ptr = "", len = 0)`
// selects the bare default EnvFilter clause — see the
// `shekyl_log_level_enabled` docstring in `src/shekyl/shekyl_log.h` and
// the `normalize_target_accepts_empty` unit test in
// `rust/shekyl-logging/src/ffi.rs`.
// ---------------------------------------------------------------------------
#define MCLOG_TYPE(level, cat, color, type, x) do { \
    const ::el::Level _shekyl_lvl = (level); \
    const char* const _shekyl_cat_raw = (cat); \
    const char* const _shekyl_cat_str = _shekyl_cat_raw ? _shekyl_cat_raw : ""; \
    const std::size_t _shekyl_cat_len = _shekyl_cat_raw ? std::strlen(_shekyl_cat_raw) : 0u; \
    if (::shekyl_log_level_enabled( \
          static_cast<std::uint8_t>(_shekyl_lvl), \
          _shekyl_cat_str, \
          _shekyl_cat_len)) { \
      (void)(color); (void)(type); \
      std::stringstream _shekyl_ss; \
      _shekyl_ss << x; \
      const std::string _shekyl_msg = _shekyl_ss.str(); \
      ::shekyl_log_emit( \
        static_cast<std::uint8_t>(_shekyl_lvl), \
        _shekyl_cat_str, \
        _shekyl_cat_len, \
        __FILE__, std::strlen(__FILE__), \
        static_cast<std::uint32_t>(__LINE__), \
        ELPP_FUNC, std::strlen(ELPP_FUNC), \
        _shekyl_msg.data(), _shekyl_msg.size()); \
    } \
  } while (0)

#define MCLOG(level, cat, color, x) MCLOG_TYPE(level, cat, color, el::base::DispatchAction::NormalLog, x)
#define MCLOG_FILE(level, cat, x) MCLOG_TYPE(level, cat, el::Color::Default, el::base::DispatchAction::FileOnlyLog, x)

#define MCFATAL(cat,x) MCLOG(el::Level::Fatal,cat, el::Color::Default, x)
#define MCERROR(cat,x) MCLOG(el::Level::Error,cat, el::Color::Default, x)
#define MCWARNING(cat,x) MCLOG(el::Level::Warning,cat, el::Color::Default, x)
#define MCINFO(cat,x) MCLOG(el::Level::Info,cat, el::Color::Default, x)
#define MCDEBUG(cat,x) MCLOG(el::Level::Debug,cat, el::Color::Default, x)
#define MCTRACE(cat,x) MCLOG(el::Level::Trace,cat, el::Color::Default, x)

#define MCLOG_COLOR(level,cat,color,x) MCLOG(level,cat,color,x)
#define MCLOG_RED(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Red,x)
#define MCLOG_GREEN(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Green,x)
#define MCLOG_YELLOW(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Yellow,x)
#define MCLOG_BLUE(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Blue,x)
#define MCLOG_MAGENTA(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Magenta,x)
#define MCLOG_CYAN(level,cat,x) MCLOG_COLOR(level,cat,el::Color::Cyan,x)

#define MLOG_RED(level,x) MCLOG_RED(level,SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MLOG_GREEN(level,x) MCLOG_GREEN(level,SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MLOG_YELLOW(level,x) MCLOG_YELLOW(level,SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MLOG_BLUE(level,x) MCLOG_BLUE(level,SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MLOG_MAGENTA(level,x) MCLOG_MAGENTA(level,SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MLOG_CYAN(level,x) MCLOG_CYAN(level,SHEKYL_DEFAULT_LOG_CATEGORY,x)

#define MFATAL(x) MCFATAL(SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MERROR(x) MCERROR(SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MWARNING(x) MCWARNING(SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MINFO(x) MCINFO(SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MDEBUG(x) MCDEBUG(SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MTRACE(x) MCTRACE(SHEKYL_DEFAULT_LOG_CATEGORY,x)
#define MLOG(level,x) MCLOG(level,SHEKYL_DEFAULT_LOG_CATEGORY,el::Color::Default,x)

#define MGINFO(x) MCINFO("global",x)
#define MGINFO_RED(x) MCLOG_RED(el::Level::Info, "global",x)
#define MGINFO_GREEN(x) MCLOG_GREEN(el::Level::Info, "global",x)
#define MGINFO_YELLOW(x) MCLOG_YELLOW(el::Level::Info, "global",x)
#define MGINFO_BLUE(x) MCLOG_BLUE(el::Level::Info, "global",x)
#define MGINFO_MAGENTA(x) MCLOG_MAGENTA(el::Level::Info, "global",x)
#define MGINFO_CYAN(x) MCLOG_CYAN(el::Level::Info, "global",x)

// Mirror of `MCLOG_TYPE` with an extra `init;` hook that runs *after* the
// enabled-gate passes and *before* the message is formatted — used by
// `MIDEBUG` and similar call sites to hoist one-time setup out of the
// disabled path. The `_shekyl_cat_{raw,str,len}` caching discipline is
// identical to `MCLOG_TYPE`; keep the two macros in sync when tweaking
// either side.
#define IFLOG(level, cat, color, type, init, x) \
  do { \
    const ::el::Level _shekyl_lvl = (level); \
    const char* const _shekyl_cat_raw = (cat); \
    const char* const _shekyl_cat_str = _shekyl_cat_raw ? _shekyl_cat_raw : ""; \
    const std::size_t _shekyl_cat_len = _shekyl_cat_raw ? std::strlen(_shekyl_cat_raw) : 0u; \
    if (::shekyl_log_level_enabled( \
          static_cast<std::uint8_t>(_shekyl_lvl), \
          _shekyl_cat_str, \
          _shekyl_cat_len)) { \
      (void)(color); (void)(type); \
      init; \
      std::stringstream _shekyl_ss; \
      _shekyl_ss << x; \
      const std::string _shekyl_msg = _shekyl_ss.str(); \
      ::shekyl_log_emit( \
        static_cast<std::uint8_t>(_shekyl_lvl), \
        _shekyl_cat_str, \
        _shekyl_cat_len, \
        __FILE__, std::strlen(__FILE__), \
        static_cast<std::uint32_t>(__LINE__), \
        ELPP_FUNC, std::strlen(ELPP_FUNC), \
        _shekyl_msg.data(), _shekyl_msg.size()); \
    } \
  } while(0)
#define MIDEBUG(init, x) IFLOG(el::Level::Debug, SHEKYL_DEFAULT_LOG_CATEGORY, el::Color::Default, el::base::DispatchAction::NormalLog, init, x)


#define LOG_ERROR(x) MERROR(x)
#define LOG_PRINT_L0(x) MWARNING(x)
#define LOG_PRINT_L1(x) MINFO(x)
#define LOG_PRINT_L2(x) MDEBUG(x)
#define LOG_PRINT_L3(x) MTRACE(x)
#define LOG_PRINT_L4(x) MTRACE(x)

#define _dbg3(x) MTRACE(x)
#define _dbg2(x) MDEBUG(x)
#define _dbg1(x) MDEBUG(x)
#define _info(x) MINFO(x)
#define _note(x) MDEBUG(x)
#define _fact(x) MDEBUG(x)
#define _mark(x) MDEBUG(x)
#define _warn(x) MWARNING(x)
#define _erro(x) MERROR(x)

// Retired under the tracing migration: thread naming is handled by the
// Rust subscriber's formatter (`%thread` equivalent emitted automatically),
// so the legacy helper becomes a no-op that still swallows its argument
// to keep `-Wunused-value` quiet at historical call sites.
#define MLOG_SET_THREAD_NAME(x) ((void)(x))

#ifndef LOCAL_ASSERT
#include <assert.h>
#if (defined _MSC_VER)
#define LOCAL_ASSERT(expr) {if(epee::debug::get_set_enable_assert()){_ASSERTE(expr);}}
#else
#define LOCAL_ASSERT(expr)
#endif

#endif

std::string mlog_get_default_log_path(const char *default_filename);
void mlog_configure(const std::string &filename_base, bool console, const std::size_t max_log_file_size = MAX_LOG_FILE_SIZE, const std::size_t max_log_files = MAX_LOG_FILES);
void mlog_set_categories(const char *categories);
std::string mlog_get_categories();
void mlog_set_log_level(int level);
void mlog_set_log(const char *log);

namespace epee
{
namespace debug
{
  inline bool get_set_enable_assert(bool set = false, bool v = false)
  {
    static bool e = true;
    if(set)
      e = v;
    return e;
  }
}



#define ENDL std::endl

#define TRY_ENTRY()   try {
#define CATCH_ENTRY(location, return_val) } \
  catch(const std::exception& ex) \
{ \
  (void)(ex); \
  LOG_ERROR("Exception at [" << location << "], what=" << ex.what()); \
  return return_val; \
}\
  catch(...)\
{\
  LOG_ERROR("Exception at [" << location << "], generic exception \"...\"");\
  return return_val; \
}

#define CATCH_ENTRY_L0(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L1(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L2(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L3(lacation, return_val) CATCH_ENTRY(lacation, return_val)
#define CATCH_ENTRY_L4(lacation, return_val) CATCH_ENTRY(lacation, return_val)


#define ASSERT_MES_AND_THROW(message) {LOG_ERROR(message); std::stringstream ss; ss << message; throw std::runtime_error(ss.str());}
#define CHECK_AND_ASSERT_THROW_MES(expr, message) do {if(!(expr)) ASSERT_MES_AND_THROW(message);} while(0)


#ifndef CHECK_AND_ASSERT
#define CHECK_AND_ASSERT(expr, fail_ret_val)   do{if(!(expr)){LOCAL_ASSERT(expr); return fail_ret_val;};}while(0)
#endif

#ifndef CHECK_AND_ASSERT_MES
#define CHECK_AND_ASSERT_MES(expr, fail_ret_val, message)   do{if(!(expr)) {LOG_ERROR(message); return fail_ret_val;};}while(0)
#endif

#ifndef CHECK_AND_NO_ASSERT_MES_L
#define CHECK_AND_NO_ASSERT_MES_L(expr, fail_ret_val, l, message)   do{if(!(expr)) {LOG_PRINT_L##l(message); /*LOCAL_ASSERT(expr);*/ return fail_ret_val;};}while(0)
#endif

#ifndef CHECK_AND_NO_ASSERT_MES
#define CHECK_AND_NO_ASSERT_MES(expr, fail_ret_val, message) CHECK_AND_NO_ASSERT_MES_L(expr, fail_ret_val, 0, message)
#endif

#ifndef CHECK_AND_NO_ASSERT_MES_L1
#define CHECK_AND_NO_ASSERT_MES_L1(expr, fail_ret_val, message) CHECK_AND_NO_ASSERT_MES_L(expr, fail_ret_val, 1, message)
#endif


#ifndef CHECK_AND_ASSERT_MES_NO_RET
#define CHECK_AND_ASSERT_MES_NO_RET(expr, message)   do{if(!(expr)) {LOG_ERROR(message); return;};}while(0)
#endif


#ifndef CHECK_AND_ASSERT_MES2
#define CHECK_AND_ASSERT_MES2(expr, message)   do{if(!(expr)) {LOG_ERROR(message); };}while(0)
#endif

enum console_colors
{
  console_color_default,
  console_color_white,
  console_color_red,
  console_color_green,
  console_color_blue,
  console_color_cyan,
  console_color_magenta,
  console_color_yellow
};

bool is_stdout_a_tty();
void set_console_color(int color, bool bright);
void reset_console_color();

}

extern "C"
{

#endif

#if defined(__GNUC__) || defined(__clang__)
#define ATTRIBUTE_PRINTF __attribute__((format(printf, 2, 3)))
#else
#define ATTRIBUTE_PRINTF
#endif

bool merror(const char *category, const char *format, ...) ATTRIBUTE_PRINTF;
bool mwarning(const char *category, const char *format, ...) ATTRIBUTE_PRINTF;
bool minfo(const char *category, const char *format, ...) ATTRIBUTE_PRINTF;
bool mdebug(const char *category, const char *format, ...) ATTRIBUTE_PRINTF;
bool mtrace(const char *category, const char *format, ...) ATTRIBUTE_PRINTF;

#ifdef __cplusplus

}

#endif

#endif //_MISC_LOG_EX_H_
