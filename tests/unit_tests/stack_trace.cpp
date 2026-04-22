// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Edge-case coverage for the `src/common/stack_trace.cpp`
// `__cxa_throw` hook after Chore #2 (shekyl-logging migration).
//
// Before Chore #2 none of these assertions were writable:
//   - `ST_LOG` delegated to easylogging++'s `CINFO` with the
//     `FileOnlyLog` dispatch action, which was a silent no-op
//     whenever `ELPP` hadn't been initialized. `tests/unit_tests`
//     never initializes `ELPP`, so every exception threw through
//     the hook with no observable output — there was nothing to
//     assert.
//   - The `dlsym(RTLD_NEXT, "__cxa_throw")` lookup ran once per
//     throw and silently no-op'd on a NULL return, so a failed
//     resolution would corrupt the in-flight exception without any
//     operator-visible signal.
//
// Chore #2 redirected `ST_LOG` to a direct `std::fwrite(..., stderr)`
// and added an explicit `std::abort` (plus diagnostic) on a NULL
// `dlsym` resolution. The per-throw `dlsym` call itself is
// intentionally preserved: caching it behind `std::call_once` or a
// function-local `static` triggers the C++ ABI's one-shot guard
// (`__cxa_guard_acquire` / pthread_once-equivalent), which we can't
// safely enter from inside the `__cxa_throw` wrapper with an
// exception half-built. These tests lock in the resulting
// invariants so a future refactor can't silently reintroduce
// either the Rust-FFI call during exception flight (a hazard
// documented in the `ST_LOG` comment block) or a caching scheme
// that re-enters the C++ ABI's init machinery during a throw.
//
// The hook is only installed when the build opted into
// `-DSTACK_TRACE=ON` (see the `DEFAULT_STACK_TRACE` block in the
// root `CMakeLists.txt`). The tests probe for installation at
// runtime via a sacrificial throw and `GTEST_SKIP()` when the
// probe comes back empty, so they're safe to run on every target
// that builds `unit_tests`.

#include "gtest/gtest.h"

#include "common/stack_trace.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#if defined(_WIN32)

// The `dup2` + `pipe` stderr-capture path below isn't implemented
// against Win32 `_pipe` / `_dup2`, so we skip unconditionally on
// Windows regardless of whether `STACK_TRACE` happens to be enabled
// for the current toolchain. The Linux legs exercise the same hook
// source.
//
// Note on `STACK_TRACE` defaults: the root `CMakeLists.txt` selector
// (`DEFAULT_STACK_TRACE`) is *not* uniformly `OFF` on Windows — on
// MSYS2/MSVC it probes for libunwind and defaults to `ON` when found,
// so we deliberately do not predicate this skip on the STACK_TRACE
// value. The stderr-capture gap is the binding constraint.
TEST(stack_trace, not_covered_on_windows)
{
  GTEST_SKIP() << "stderr capture via dup2/pipe is not wired for Win32 "
                  "in this test file; the Linux legs exercise the same "
                  "hook source.";
}

#else

#include <fcntl.h>
#include <unistd.h>

namespace
{

// Redirect `stderr` (fd 2) into a pipe for the lifetime of the
// guard. `drain()` reads everything accumulated so far; the
// destructor (or `restore()`) puts the original `stderr` back.
//
// The pipe read end is put in non-blocking mode so `drain()` can
// empty it without risk of a deadlock if the hook produced less
// than a full buffer. We also `fflush(stderr)` before the restore
// so any libc-buffered bytes land in the capture, not in the
// post-restore descriptor.
class StderrCapture
{
public:
  StderrCapture() { install(); }
  ~StderrCapture() { restore(); }

  StderrCapture(const StderrCapture &) = delete;
  StderrCapture &operator=(const StderrCapture &) = delete;

  // Read and return everything currently in the pipe. Safe to call
  // multiple times; each call only returns bytes written since the
  // previous call.
  std::string drain()
  {
    if (read_fd_ < 0)
      return std::string();
    std::fflush(stderr);
    std::string out;
    char buf[4096];
    for (;;)
    {
      const ssize_t n = ::read(read_fd_, buf, sizeof(buf));
      if (n > 0)
      {
        out.append(buf, static_cast<std::size_t>(n));
        continue;
      }
      break;
    }
    return out;
  }

  void restore()
  {
    if (saved_fd_ >= 0)
    {
      std::fflush(stderr);
      ::dup2(saved_fd_, STDERR_FILENO);
      ::close(saved_fd_);
      saved_fd_ = -1;
    }
    if (read_fd_ >= 0)
    {
      ::close(read_fd_);
      read_fd_ = -1;
    }
  }

  bool usable() const { return saved_fd_ >= 0 && read_fd_ >= 0; }

private:
  void install()
  {
    std::fflush(stderr);
    saved_fd_ = ::dup(STDERR_FILENO);
    if (saved_fd_ < 0)
      return;
    int fds[2];
    if (::pipe(fds) != 0)
    {
      ::close(saved_fd_);
      saved_fd_ = -1;
      return;
    }
    if (::fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0)
    {
      ::close(fds[0]);
      ::close(fds[1]);
      ::close(saved_fd_);
      saved_fd_ = -1;
      return;
    }
    if (::dup2(fds[1], STDERR_FILENO) < 0)
    {
      ::close(fds[0]);
      ::close(fds[1]);
      ::close(saved_fd_);
      saved_fd_ = -1;
      return;
    }
    ::close(fds[1]);
    read_fd_ = fds[0];
  }

  int saved_fd_ = -1;
  int read_fd_ = -1;
};

// Runtime probe: throw + catch a harmless exception and check
// whether the hook emitted its `[stacktrace]` prefix to stderr.
// When `STACK_TRACE` is compiled out, the probe comes back empty
// and the test skips.
bool hook_is_installed()
{
  StderrCapture cap;
  if (!cap.usable())
    return false;
  try
  {
    throw std::runtime_error("stack_trace_probe");
  }
  catch (const std::exception &)
  {
  }
  return cap.drain().find("[stacktrace]") != std::string::npos;
}

std::size_t count_occurrences(const std::string &haystack, const std::string &needle)
{
  if (needle.empty())
    return 0;
  std::size_t count = 0;
  for (std::size_t pos = 0; (pos = haystack.find(needle, pos)) != std::string::npos;
       pos += needle.size())
  {
    ++count;
  }
  return count;
}

} // namespace

// The hook must forward control to the real `__cxa_throw`; the
// thrown exception needs to land in the user-level `catch`. A
// regression that (for example) called a NULL `__real___cxa_throw`
// would abort the process and never reach the assertion.
TEST(stack_trace, throw_and_catch_survives)
{
  bool caught = false;
  std::string what;
  try
  {
    throw std::runtime_error("alive");
  }
  catch (const std::runtime_error &e)
  {
    caught = true;
    what = e.what();
  }
  EXPECT_TRUE(caught);
  EXPECT_EQ(what, "alive");
}

// Pre-Chore #2 this assertion was impossible to write:
// `ST_LOG` was a silent no-op in unit_tests because `ELPP` was
// never initialized. Post-Chore #2 every throw emits a
// `[stacktrace]` block to stderr directly (no Rust FFI hop), so
// we can pin down the exact shape of the output and catch any
// future regression that routes it back through the logging
// subsystem.
TEST(stack_trace, emits_to_stderr_not_rust_log)
{
  if (!hook_is_installed())
    GTEST_SKIP() << "STACK_TRACE is not enabled in this build";

  StderrCapture cap;
  ASSERT_TRUE(cap.usable());
  try
  {
    throw std::runtime_error("diagnostic");
  }
  catch (const std::exception &)
  {
  }
  const std::string out = cap.drain();

  EXPECT_NE(out.find("[stacktrace] Exception:"), std::string::npos) << out;
  EXPECT_NE(out.find("std::runtime_error"), std::string::npos) << out;
  EXPECT_NE(out.find("[stacktrace] Unwound call stack:"), std::string::npos) << out;

  // Guard against a future refactor that routes the hook back
  // through `shekyl_log_emit`. Rust's `tracing` default formatter
  // prefixes each line with an RFC-3339 timestamp and a level
  // tag (`" INFO stacktrace:"`); the raw stderr path we installed
  // intentionally avoids both. Either marker showing up here
  // means the hook is doing work inside the Rust subscriber
  // during the `__cxa_throw` window — exactly the hazard the
  // `ST_LOG` comment block in `src/common/stack_trace.cpp`
  // warns against.
  EXPECT_EQ(out.find(" INFO stacktrace:"), std::string::npos) << out;
  EXPECT_EQ(out.find(" INFO  stacktrace:"), std::string::npos) << out;
}

// Repeated throws must all pass cleanly through the hook, with
// exactly one `[stacktrace] Exception:` / `Unwound call stack:`
// pair per throw. This is the main line of defense against two
// classes of regression:
//
//   1. A caching refactor that routes `dlsym` through
//      `std::call_once` or a function-local `static` — both of
//      those trigger the C++ ABI's `__cxa_guard_*` init path,
//      which we can't safely enter from inside the
//      `__cxa_throw` wrapper. The observable symptom on glibc
//      is a silent process abort on the first throw with no
//      diagnostic output, which surfaces here as the subsuite
//      aborting before the `EXPECT_EQ` below runs.
//
//   2. A forwarding regression (NULL `__real___cxa_throw`,
//      self-loop, mis-cast pointer) that fails to hand the
//      exception off to libstdc++ — those also abort, again
//      before the final assertion.
//
// A clean run reaches the assertion and observes `kThrows`
// `[stacktrace]` blocks in the drained stderr.
TEST(stack_trace, repeated_throws_do_not_crash_and_emit_once_per_throw)
{
  if (!hook_is_installed())
    GTEST_SKIP() << "STACK_TRACE is not enabled in this build";

  StderrCapture cap;
  ASSERT_TRUE(cap.usable());

  constexpr int kThrows = 16;
  int caught = 0;
  for (int i = 0; i < kThrows; ++i)
  {
    try
    {
      throw std::runtime_error(std::to_string(i));
    }
    catch (const std::exception &)
    {
      ++caught;
    }
  }
  EXPECT_EQ(caught, kThrows);

  const std::string out = cap.drain();
  EXPECT_EQ(count_occurrences(out, "[stacktrace] Exception:"),
            static_cast<std::size_t>(kThrows))
      << out;
  EXPECT_EQ(count_occurrences(out, "[stacktrace] Unwound call stack:"),
            static_cast<std::size_t>(kThrows))
      << out;
}

// Exception type demangling was already working before Chore #2,
// but it was never *asserted*, and the new stderr-direct path
// goes through a `(std::string("Exception: ") + dsym).c_str()`
// temporary that would be easy to break during future cleanup.
TEST(stack_trace, demangles_exception_type)
{
  if (!hook_is_installed())
    GTEST_SKIP() << "STACK_TRACE is not enabled in this build";

  StderrCapture cap;
  ASSERT_TRUE(cap.usable());
  try
  {
    throw std::out_of_range("range");
  }
  catch (const std::exception &)
  {
  }
  const std::string out = cap.drain();
  EXPECT_NE(out.find("std::out_of_range"), std::string::npos) << out;
  // If demangling regressed and we emitted the mangled form, it
  // would contain the Itanium ABI tokens below. Pin them as
  // negative markers so the failure message points at the real
  // cause rather than a vague "unexpected substring".
  EXPECT_EQ(out.find("St12out_of_range"), std::string::npos) << out;
}

// Nested throws (throw-from-a-destructor-like pattern) exercise
// the hook while the previous exception object is still live on
// the exception stack. The hook must not confuse the two, and
// each throw must still forward to the real `__cxa_throw`.
TEST(stack_trace, nested_throws_both_propagate)
{
  bool outer_caught = false;
  bool inner_caught = false;
  try
  {
    try
    {
      throw std::runtime_error("inner");
    }
    catch (const std::exception &)
    {
      inner_caught = true;
      throw std::runtime_error("outer");
    }
  }
  catch (const std::exception &e)
  {
    outer_caught = true;
    EXPECT_STREQ(e.what(), "outer");
  }
  EXPECT_TRUE(inner_caught);
  EXPECT_TRUE(outer_caught);
}

#endif // !_WIN32
