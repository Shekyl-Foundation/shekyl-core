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


#ifndef _MLOG_H_
#define _MLOG_H_

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING  0x0004
#endif
#endif

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <iostream>
#include <string>
#include <boost/filesystem.hpp>
// NOTE: easylogging++.h is no longer included. Every piece of state
// that used to live in easylogging++'s `el::Loggers` / `el::Helpers`
// singletons now lives in the Rust `shekyl-logging` subscriber, which
// is reached through `src/shekyl/shekyl_log.h`. `misc_log_ex.h`'s
// compatibility shim (enabled again for this TU now that
// `EASYLOGGINGPP_H` is undefined) turns the M*/MC* macros below into
// direct `shekyl_log_emit` calls.
#include "string_tools.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_log.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "logging"

using namespace epee;

std::string mlog_get_default_log_path(const char *default_filename)
{
  // Resolve the binary name exactly as the legacy implementation did
  // (strip the extension off `argv[0]`, fall back to `default_filename`
  // when the module name is empty). The directory contract is what
  // changes: instead of sitting next to the binary
  // (`<module_folder>/<binary>.log`), the active log file now lives
  // under `~/.shekyl/logs/<binary>.log`, matching rule 93's
  // version-symbol migration and `shekyl_log_default_path`'s
  // `<home>/.shekyl/logs/…` contract in
  // `src/shekyl/shekyl_log.h`. The operator-visible path is reported
  // through `--log-file` CLI output and through the `RPC::get_log_
  // categories` response body; both surfaces are preserved.
  std::string binary_name = epee::string_tools::get_current_module_name();
  const std::string::size_type dot = binary_name.rfind('.');
  if (dot != std::string::npos)
    binary_name.erase(dot, binary_name.size());
  if (binary_name.empty())
    binary_name = default_filename ? default_filename : "";

  // Peel any trailing ".log" from the fallback filename so we never
  // produce `shekyld.log.log`.
  if (binary_name.size() > 4 &&
      binary_name.compare(binary_name.size() - 4, 4, ".log") == 0)
    binary_name.erase(binary_name.size() - 4, 4);

  // Two-call convention: ask the FFI for the required buffer size,
  // then re-ask with an exact-fit buffer. `shekyl_log_default_path`
  // returns the total byte length regardless of truncation (see
  // `src/shekyl/shekyl_log.h` buffer-sizing convention) and never
  // writes a NUL.
  const size_t needed = ::shekyl_log_default_path(
    binary_name.data(), binary_name.size(),
    nullptr, 0);
  if (needed == 0)
  {
    // Home directory unresolved or UTF-8 failure. Fall back to the
    // current directory so `fopen(path, ...)` at the call site still
    // stands a chance of succeeding — mirrors the legacy behavior of
    // returning a relative path when `get_current_module_folder()`
    // resolved to empty.
    return binary_name.empty() ? std::string() : binary_name + ".log";
  }
  std::string out;
  out.resize(needed);
  const size_t wrote = ::shekyl_log_default_path(
    binary_name.data(), binary_name.size(),
    out.empty() ? nullptr : &out[0], out.size());
  if (wrote != needed)
  {
    // Between the two calls the answer shrank; defensive guard so we
    // never return uninitialized tail bytes.
    out.resize(wrote);
  }
  return out;
}

static const char *get_default_categories(int level)
{
  const char *categories = "";
  switch (level)
  {
    case 0:
      categories = "*:WARNING,net:FATAL,net.http:FATAL,net.ssl:FATAL,net.p2p:FATAL,net.cn:FATAL,daemon.rpc:FATAL,global:INFO,verify:FATAL,serialization:FATAL,daemon.rpc.payment:ERROR,stacktrace:INFO,logging:INFO,msgwriter:INFO";
      break;
    case 1:
      categories = "*:INFO,global:INFO,stacktrace:INFO,logging:INFO,msgwriter:INFO,perf.*:DEBUG";
      break;
    case 2:
      categories = "*:DEBUG";
      break;
    case 3:
      categories = "*:TRACE,*.dump:DEBUG";
      break;
    case 4:
      categories = "*:TRACE";
      break;
    default:
      break;
  }
  return categories;
}

#ifdef WIN32
bool EnableVTMode()
{
  // Set output mode to handle virtual terminal sequences
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut == INVALID_HANDLE_VALUE)
  {
    return false;
  }

  DWORD dwMode = 0;
  if (!GetConsoleMode(hOut, &dwMode))
  {
    return false;
  }

  dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  if (!SetConsoleMode(hOut, dwMode))
  {
    return false;
  }
  return true;
}
#endif

void mlog_configure(const std::string &filename_base, bool console, const std::size_t max_log_file_size, const std::size_t max_log_files)
{
  // Translate the single-string `filename_base` contract into the
  // Rust FFI's `(dir, prefix)` shape. Empty filename_base means
  // "stderr only" (used by `cn_deserialize`, `object_sizes`,
  // `dns_checks`, `on_startup` -> util.cpp); anything else splits
  // into (parent, filename) so the live file is
  // `<parent>/<filename>` and rotated archives become
  // `<parent>/<filename>-YYYY-MM-DD-HH-MM-SS`, matching the legacy
  // easylogging++ pre-roll-out callback's naming.
  //
  // The `console` flag no longer has a direct counterpart: the
  // tracing subscriber always emits to stderr, and per
  // `.cursor/rules/82-failure-mode-ux.mdc` errors must be visible
  // on stderr at all times. The single in-tree caller that passes
  // `console=false` is `tests/unit_tests/logging.cpp`, and those
  // tests are scheduled to be rewritten in the follow-up
  // `unit-tests-logging` commit to assert against dup2'd stderr
  // capture instead of the file sink.
  (void)console;

  const uint8_t fallback = SHEKYL_LOG_LEVEL_WARNING;

  int32_t rc = SHEKYL_LOG_OK;
  if (filename_base.empty())
  {
    rc = ::shekyl_log_init_stderr(fallback);
  }
  else
  {
    const boost::filesystem::path p(filename_base);
    const std::string prefix = p.filename().string();
    const boost::filesystem::path parent =
      p.has_parent_path() ? p.parent_path() : boost::filesystem::path(".");
    const std::string dir = parent.string();

    const uint64_t max_bytes = static_cast<uint64_t>(max_log_file_size);
    // max_log_files == 0 in legacy code meant "unbounded retention"
    // *and* was also how tests asked for size 0 rotation. The FFI
    // contract is `max_bytes == 0 => no rotation`, `max_files == 0
    // => prune off`; we map both 0-sentinels faithfully.
    const uint32_t max_files = static_cast<uint32_t>(max_log_files);

    rc = ::shekyl_log_init_file(
      dir.data(), dir.size(),
      prefix.data(), prefix.size(),
      fallback,
      max_bytes,
      max_files);
  }

  // `SHEKYL_LOG_ERR_ALREADY_INIT` is expected when a second binary-
  // entry point (e.g. wallet_args inside a wallet RPC subprocess)
  // reaches this function after the daemon's own init already ran —
  // the subscriber is global and first-caller-wins. Other error
  // codes leave the tree uninitialized and the subsequent
  // `mlog_set_log` call turns into a no-op; there is no safe
  // recovery here, so we surface the diagnostic via stderr and keep
  // moving. The operator will see missing logs and can correlate
  // with the one-shot stderr line.
  if (rc != SHEKYL_LOG_OK && rc != SHEKYL_LOG_ERR_ALREADY_INIT)
  {
    char errbuf[256] = {0};
    const size_t en = ::shekyl_log_last_error_message(errbuf, sizeof(errbuf) - 1);
    std::fprintf(stderr,
      "mlog_configure: shekyl_log_init_* failed (rc=%d): %.*s\n",
      static_cast<int>(rc), static_cast<int>(en), errbuf);
  }

  // Seed the filter. Precedence order, preserved from the legacy
  // implementation with `MONERO_LOGS` renamed to `SHEKYL_LOG` per
  // `.cursor/rules/93-legacy-symbol-migration.mdc`:
  //
  //   1. If `SHEKYL_LOG` is set, the Rust side has already applied
  //      it inside `shekyl_log_init_*`; we skip explicit reseeding
  //      so we don't clobber the operator's directive.
  //   2. Otherwise, apply the rich level-0 default preset
  //      (the legacy `*:WARNING,net:FATAL,…` spec from
  //      `get_default_categories(0)`). Without this, binaries
  //      built without the `dev-env-fallback` feature flag would
  //      boot with a bare `*:WARNING` filter and flood the
  //      `net.*` categories with noise that the legacy preset
  //      historically silenced.
  //
  // `MONERO_LOG_FORMAT` support is retired entirely — format
  // strings are owned by the Rust subscriber's layer stack and
  // are not operator-tunable. Documented in `docs/CHANGELOG.md`
  // under the V3.x alpha.0 format-break entry.
  const char *env_spec = std::getenv("SHEKYL_LOG");
  if (!env_spec || !*env_spec)
  {
    mlog_set_log(get_default_categories(0));
  }

#ifdef WIN32
  EnableVTMode();
#endif
}

void mlog_set_categories(const char *categories)
{
  // The Rust translator keeps its own `current_spec` and handles
  // `+foo:LEVEL` / `-foo` modifiers internally (see
  // `rust/shekyl-logging/src/legacy.rs::merge_modifier`), so the
  // elaborate textual munging the legacy C++ body did against
  // `el::Loggers::getCategories()` is gone. We just forward the
  // bytes verbatim.
  const char *spec = categories ? categories : "";
  const size_t len = std::strlen(spec);
  const int32_t rc = ::shekyl_log_set_categories(spec, len, SHEKYL_LOG_LEVEL_WARNING);
  if (rc != SHEKYL_LOG_OK)
  {
    char errbuf[256] = {0};
    const size_t en = ::shekyl_log_last_error_message(errbuf, sizeof(errbuf) - 1);
    MERROR("mlog_set_categories rejected `" << spec
           << "` (rc=" << rc << "): " << std::string(errbuf, en));
    return;
  }
  MINFO("New log categories: " << mlog_get_categories());
}

std::string mlog_get_categories()
{
  const size_t needed = ::shekyl_log_get_categories(nullptr, 0);
  if (needed == 0)
    return std::string();
  std::string out;
  out.resize(needed);
  const size_t wrote = ::shekyl_log_get_categories(&out[0], out.size());
  if (wrote != needed)
    out.resize(wrote);
  return out;
}

void mlog_set_log_level(int level)
{
  if (level < 0 || level > 4)
  {
    MERROR("mlog_set_log_level: level " << level << " outside the 0..=4 preset range");
    return;
  }
  const int32_t rc = ::shekyl_log_set_level(static_cast<uint8_t>(level));
  if (rc != SHEKYL_LOG_OK)
  {
    char errbuf[256] = {0};
    const size_t en = ::shekyl_log_last_error_message(errbuf, sizeof(errbuf) - 1);
    MERROR("mlog_set_log_level(" << level << ") failed (rc=" << rc << "): "
           << std::string(errbuf, en));
  }
}

void mlog_set_log(const char *log)
{
  // Three accepted shapes, matching the legacy contract so CLI
  // `--log-level` / daemon-RPC `set_log_categories` callers keep
  // working without a format flag day:
  //
  //   1. ""              => pass through to `mlog_set_categories("")`
  //                         which the Rust translator interprets as
  //                         "disable all logging" (see
  //                         `TEST(logging, no_logs)`).
  //   2. "<N>"           => bare numeric preset 0..=4 → `shekyl_log_
  //                         set_level(N)`.
  //   3. "<N>,<spec>"    => legacy concatenation — preset N plus
  //                         additional category overrides — resolved
  //                         here by glueing `get_default_categories(N)`
  //                         to the tail and forwarding as one spec.
  //   4. anything else   => raw legacy spec, forwarded verbatim.
  if (!log || !*log)
  {
    mlog_set_categories("");
    return;
  }

  char *ptr = nullptr;
  const long level = std::strtol(log, &ptr, 10);

  if (ptr && *ptr)
  {
    if (*ptr == ',')
    {
      if (level < 0 || level > 4)
      {
        MERROR("mlog_set_log: numeric prefix " << level
               << " in `" << log << "` outside the 0..=4 preset range");
        return;
      }
      std::string merged(get_default_categories(static_cast<int>(level)));
      merged += ptr;
      mlog_set_categories(merged.c_str());
    }
    else
    {
      mlog_set_categories(log);
    }
  }
  else if (level >= 0 && level <= 4)
  {
    mlog_set_log_level(static_cast<int>(level));
  }
  else
  {
    MERROR("Invalid numerical log level: " << log);
  }
}

namespace epee
{

bool is_stdout_a_tty()
{
  static std::atomic<bool> initialized(false);
  static std::atomic<bool> is_a_tty(false);

  if (!initialized.load(std::memory_order_acquire))
  {
#if defined(WIN32)
    is_a_tty.store(0 != _isatty(_fileno(stdout)), std::memory_order_relaxed);
#else
    is_a_tty.store(0 != isatty(fileno(stdout)), std::memory_order_relaxed);
#endif
    initialized.store(true, std::memory_order_release);
  }

  return is_a_tty.load(std::memory_order_relaxed);
}

static bool is_nocolor()
{
  static const char *no_color_var = getenv("NO_COLOR");
  static const bool no_color = no_color_var && *no_color_var; // apparently, NO_COLOR=0 means no color too (as per no-color.org)
  return no_color;
}

void set_console_color(int color, bool bright)
{
  if (!is_stdout_a_tty())
    return;

  if (is_nocolor())
    return;

  switch(color)
  {
  case console_color_default:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE| (bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;37m";
      else
        std::cout << "\033[0m";
#endif
    }
    break;
  case console_color_white:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | (bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;37m";
      else
        std::cout << "\033[0;37m";
#endif
    }
    break;
  case console_color_red:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_RED | (bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;31m";
      else
        std::cout << "\033[0;31m";
#endif
    }
    break;
  case console_color_green:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_GREEN | (bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;32m";
      else
        std::cout << "\033[0;32m";
#endif
    }
    break;

  case console_color_blue:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_BLUE | FOREGROUND_INTENSITY);//(bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;34m";
      else
        std::cout << "\033[0;34m";
#endif
    }
    break;

  case console_color_cyan:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_GREEN | FOREGROUND_BLUE | (bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;36m";
      else
        std::cout << "\033[0;36m";
#endif
    }
    break;

  case console_color_magenta:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_BLUE | FOREGROUND_RED | (bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;35m";
      else
        std::cout << "\033[0;35m";
#endif
    }
    break;

  case console_color_yellow:
    {
#ifdef WIN32
      HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
      SetConsoleTextAttribute(h_stdout, FOREGROUND_RED | FOREGROUND_GREEN | (bright ? FOREGROUND_INTENSITY:0));
#else
      if(bright)
        std::cout << "\033[1;33m";
      else
        std::cout << "\033[0;33m";
#endif
    }
    break;

  }
}

void reset_console_color() {
  if (!is_stdout_a_tty())
    return;

  if (is_nocolor())
    return;

#ifdef WIN32
  HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
  SetConsoleTextAttribute(h_stdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
  std::cout << "\033[0m";
  std::cout.flush();
#endif
}

}

// C-ABI varargs shim for merror/mwarning/minfo/mdebug/mtrace. Routes
// straight through the shekyl_log FFI rather than the M*/MC* macros
// because the macros require a streaming `<<` expression at the call
// site; these legacy printf-style helpers already have a raw
// `char*` buffer, so going directly to `shekyl_log_emit` skips an
// unnecessary `stringstream` round-trip.
static bool mlog(uint8_t level, const char *category, const char *format, va_list ap) noexcept
{
  int size = 0;
  char *p = NULL;
  va_list apc;
  bool ret = true;

  /* Determine required size */
  va_copy(apc, ap);
  size = vsnprintf(p, size, format, apc);
  va_end(apc);
  if (size < 0)
    return false;

  size++;             /* For '\0' */
  p = (char*)malloc(size);
  if (p == NULL)
    return false;

  size = vsnprintf(p, size, format, ap);
  if (size < 0)
  {
    free(p);
    return false;
  }

  try
  {
    const size_t msg_len = (size > 0) ? static_cast<size_t>(size) : 0u;
    const size_t cat_len = category ? std::strlen(category) : 0u;
    if (shekyl_log_level_enabled(level, category ? category : "", cat_len))
    {
      shekyl_log_emit(
        level,
        category ? category : "", cat_len,
        nullptr, 0u,
        0u,
        nullptr, 0u,
        p, msg_len);
    }
  }
  catch(...)
  {
    ret = false;
  }
  free(p);

  return ret;
}

#define DEFLOG(fun,lev) \
  bool m##fun(const char *category, const char *fmt, ...) { va_list ap; va_start(ap, fmt); bool ret = mlog(SHEKYL_LOG_LEVEL_##lev, category, fmt, ap); va_end(ap); return ret; }

DEFLOG(error, ERROR)
DEFLOG(warning, WARNING)
DEFLOG(info, INFO)
DEFLOG(debug, DEBUG)
DEFLOG(trace, TRACE)

#undef DEFLOG

#endif //_MLOG_H_
