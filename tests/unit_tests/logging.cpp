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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

// V3.x alpha.0 rewrite. The pre-migration test body drove the
// vendored `easylogging++` tree directly (`el::Logger`,
// `el::Configurations`, `mlog_configure(path, false, 0)` to
// redirect to a temp file, then `load_file_to_string` to inspect
// the output). That model is incompatible with the Rust-side
// `shekyl-logging` subscriber installed by `unit_tests/main.cpp`
// at startup: the subscriber is process-global and first-caller
// wins, so reconfiguring the sink mid-process returns
// `SHEKYL_LOG_ERR_ALREADY_INIT` and the file-based assertions
// degrade to "did not crash" rather than "emitted the expected
// bytes". It is also no longer sound: `el::Logger` /
// `el::Configurations` no longer exist, and the C++ shim in
// `contrib/epee/include/misc_log_ex.h` only reimplements enough of
// the `el::` namespace to keep the `MINFO` / `MDEBUG` / etc.
// macro expansions compiling.
//
// The replacement strategy:
//
//   1. Capture stderr by `dup2`'ing a pipe over `STDERR_FILENO`
//      for the duration of a test. The Rust subscriber's stderr
//      layer is built with `fmt::layer().with_writer(std::io::stderr)`
//      (see `rust/shekyl-logging/src/lib.rs::install_subscriber_inner`),
//      which writes unbuffered through `libc::STDERR_FILENO`, so the
//      redirect catches every event the subscriber would otherwise
//      have sent to the operator's terminal.
//
//   2. Drive the public FFI surface through the production macros
//      (`MERROR`, `MWARNING`, `MINFO`, …) — no `el::` internals, no
//      local re-implementations of the shim. Per
//      `.cursor/rules/50-testing.mdc` "Test the production code, not
//      a local re-implementation."
//
//   3. Assert on user-visible substrings (the emitted message body
//      and the target/category), not on the exact timestamp /
//      level-format layout; the latter is owned by
//      `tracing-subscriber`'s default `fmt::layer` and is not a
//      Shekyl-level contract (see the V3.x alpha.0 format-break
//      entry in `docs/CHANGELOG.md`).
//
// Windows is excluded wholesale. `dup2`/`pipe` exist in the
// Win32 POSIX shim but `STDERR_FILENO` semantics under MSYS2 /
// MSVC diverge enough from Unix that a portable capture fixture is
// more surface than value for this level of test. The Rust-side
// shekyl-logging crate owns the cross-platform coverage; C++-side
// tests are POSIX-only by design.

#include <cstring>
#include <string>
#include <thread>

#include "gtest/gtest.h"
#include "misc_log_ex.h"

#if !defined(_WIN32)
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace
{
#if !defined(_WIN32)
  /// RAII stderr redirector. Constructs a pipe, points
  /// `STDERR_FILENO` at its write end, and restores the original fd
  /// on destruction. `drain()` pulls whatever the Rust subscriber
  /// has written so far. Non-blocking with a short polling loop
  /// because the subscriber's stderr path is synchronous but libc's
  /// scheduling between our `MINFO(...)` call and the pipe read is
  /// not — a tight `read` loop with a ~50 ms ceiling is empirically
  /// enough on every CI runner that currently hosts `unit_tests`.
  class stderr_capture
  {
  public:
    stderr_capture()
    {
      int pipefd[2] = {-1, -1};
      if (::pipe(pipefd) != 0)
      {
        setup_error_ = std::string("pipe() failed: ") + std::strerror(errno);
        return;
      }
      // Non-blocking read so `drain()` can poll without risk of
      // hanging the test process if the subscriber emitted nothing.
      const int fl = ::fcntl(pipefd[0], F_GETFL, 0);
      if (fl == -1 || ::fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK) != 0)
      {
        setup_error_ = std::string("fcntl(O_NONBLOCK) failed: ") + std::strerror(errno);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return;
      }
      read_fd_ = pipefd[0];
      write_fd_ = pipefd[1];

      std::fflush(stderr);
      saved_stderr_ = ::dup(STDERR_FILENO);
      if (saved_stderr_ < 0)
      {
        setup_error_ = std::string("dup(STDERR_FILENO) failed: ") + std::strerror(errno);
        return;
      }
      if (::dup2(write_fd_, STDERR_FILENO) < 0)
      {
        setup_error_ = std::string("dup2 failed: ") + std::strerror(errno);
        return;
      }
      usable_ = true;
    }

    ~stderr_capture()
    {
      restore();
      if (read_fd_ >= 0) ::close(read_fd_);
      if (write_fd_ >= 0) ::close(write_fd_);
    }

    /// Pull whatever the subscriber has written to our pipe end.
    /// Polls for `timeout` total wall time; returns as soon as a
    /// read returns 0 bytes twice in a row (drained) or the timeout
    /// elapses. `fflush(stderr)` flushes any libc-buffered output
    /// but the Rust subscriber writes via `std::io::stderr` which is
    /// unbuffered on pipes, so the bulk of the payload is already
    /// resident after the emit returns.
    std::string drain(std::chrono::milliseconds timeout = std::chrono::milliseconds(100))
    {
      std::fflush(stderr);
      const auto deadline = std::chrono::steady_clock::now() + timeout;
      std::string out;
      char buf[4096];
      int empty_reads = 0;
      while (std::chrono::steady_clock::now() < deadline)
      {
        const ssize_t n = ::read(read_fd_, buf, sizeof(buf));
        if (n > 0)
        {
          out.append(buf, buf + n);
          empty_reads = 0;
        }
        else if (n == 0)
        {
          break; // writer-side closed (shouldn't happen here)
        }
        // POSIX permits `EAGAIN` and `EWOULDBLOCK` to be the same value
        // (true on Linux / glibc / musl, both defined to `11`); on
        // those platforms GCC's `-Wlogical-op` fires on
        // `errno == EAGAIN || errno == EWOULDBLOCK` because it
        // resolves to `errno == 11 || errno == 11`. A compile-time
        // split keeps the behavior correct on platforms where POSIX
        // permits them to differ (some BSDs) without tripping the
        // warning on platforms where they don't.
#if defined(EWOULDBLOCK) && (EAGAIN != EWOULDBLOCK)
        else if (errno == EAGAIN || errno == EWOULDBLOCK)
#else
        else if (errno == EAGAIN)
#endif
        {
          if (++empty_reads >= 2 && !out.empty()) break;
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        else
        {
          break;
        }
      }
      return out;
    }

    void restore()
    {
      if (saved_stderr_ < 0) return;
      std::fflush(stderr);
      ::dup2(saved_stderr_, STDERR_FILENO);
      ::close(saved_stderr_);
      saved_stderr_ = -1;
    }

    /// True iff the pipe / `dup2` plumbing succeeded. Tests that
    /// assert the *absence* of output (e.g. `TEST(logging, no_logs)`)
    /// must gate on this — a `stderr_capture` whose setup failed
    /// silently would leave stderr pointing at the original fd, and
    /// `drain()` would return an empty string regardless of whether
    /// the subscriber actually emitted, producing a false negative.
    /// Hard-asserting with `ASSERT_TRUE(cap.usable())` turns that
    /// failure into a loud, debuggable test error that surfaces
    /// `setup_error()` instead of a silently passing no-op test.
    bool usable() const { return usable_; }
    const std::string &setup_error() const { return setup_error_; }

  private:
    int read_fd_ = -1;
    int write_fd_ = -1;
    int saved_stderr_ = -1;
    bool usable_ = false;
    std::string setup_error_;
  };
#endif // !_WIN32
} // namespace

#if defined(_WIN32)

// The whole file compiles but becomes a single skipped test so the
// CTest row stays visible in CI. See the file-level note above.
TEST(logging, skipped_on_windows)
{
  GTEST_SKIP() << "stderr-capture tests are POSIX-only; the Rust "
                  "shekyl-logging crate owns Windows coverage.";
}

#else

// Legacy-parity coverage for `TEST(logging, no_logs)`: when the
// active filter silences everything, the production macros must not
// emit anything — not a header, not a timestamp, not the category,
// nothing. The pre-migration test checked this by writing to a temp
// file and asserting the file was empty; we check it by capturing
// stderr and asserting the captured buffer contains no marker text.
//
// `mlog_set_categories("")` routes through the Rust translator's
// runtime empty-spec branch, which returns the EnvFilter `"off"`
// directive (see `rust/shekyl-logging/src/legacy.rs::translate`).
// `"off"` is the one directive that disables every level — including
// the error/fatal band that the legacy `*:FATAL` spec would preserve.
// Using the empty-spec path rather than `*:FATAL` therefore preserves
// the *observable* behavior of the original test (no output at all)
// even though the FATAL-vs-ERROR tier merge inside `tracing` would
// otherwise keep MERROR / MFATAL events reaching stderr under any
// level-based directive.
TEST(logging, no_logs)
{
  mlog_set_categories("");
  stderr_capture cap;
  ASSERT_TRUE(cap.usable())
    << "stderr_capture setup failed (" << cap.setup_error()
    << "); an empty drain below would be a false negative.";
  MFATAL("marker-no-logs-fatal");
  MERROR("marker-no-logs-error");
  MWARNING("marker-no-logs-warn");
  MINFO("marker-no-logs-info");
  MDEBUG("marker-no-logs-debug");
  MTRACE("marker-no-logs-trace");
  const std::string out = cap.drain();
  cap.restore();

  // Empty-spec routes through the translator's `"off"` branch (see
  // `rust/shekyl-logging/src/legacy.rs::translate`); `"off"` disables
  // every level including error/fatal. Nothing at all should reach
  // stderr — not even a header line, not a trailing newline. Assert
  // on `out.empty()` rather than "the marker substring isn't there"
  // so that a subscriber that somehow emits *any* bytes under the
  // `"off"` filter surfaces as a loud failure rather than slipping
  // through on a substring check.
  EXPECT_TRUE(out.empty())
    << "captured output under `off` filter was non-empty (" << out.size()
    << " bytes):\n" << out;
}

// Positive control for the stderr pipeline: with the filter wide
// open, an info-level emit through the production macro reaches the
// subscriber and the subscriber writes it to stderr in a form that
// contains the message text. The exact surrounding format
// (timestamp, level token, target token) is tracing-subscriber's
// contract, not Shekyl's — we only assert the message body survives
// round-trip.
TEST(logging, info_reaches_stderr)
{
  mlog_set_categories("*:INFO");
  stderr_capture cap;
  ASSERT_TRUE(cap.usable())
    << "stderr_capture setup failed: " << cap.setup_error();
  MGINFO("marker-info-reaches-stderr");
  const std::string out = cap.drain();
  cap.restore();

  EXPECT_NE(out.find("marker-info-reaches-stderr"), std::string::npos)
    << "expected MGINFO payload missing from captured stderr:\n"
    << out;
}

// The level threshold is honored in the forward direction: with the
// filter set to WARNING, an INFO emit does not appear but a WARNING
// emit does. Exercises the `shekyl_log_level_enabled` short-circuit
// inside `MCLOG_TYPE` (the one that avoids building the
// stringstream when the event would be filtered out).
TEST(logging, level_threshold_is_respected)
{
  mlog_set_categories("*:WARNING");
  stderr_capture cap;
  ASSERT_TRUE(cap.usable())
    << "stderr_capture setup failed: " << cap.setup_error();
  MINFO("marker-should-not-appear");
  MWARNING("marker-should-appear");
  const std::string out = cap.drain();
  cap.restore();

  EXPECT_EQ(out.find("marker-should-not-appear"), std::string::npos)
    << "info-level marker leaked through a WARNING filter:\n" << out;
  EXPECT_NE(out.find("marker-should-appear"), std::string::npos)
    << "warning-level marker missing from captured stderr:\n" << out;
}

// Category routing works end-to-end: a category-scoped emit with
// that category elevated to TRACE reaches stderr, while a different
// category's emit at the same level does not (because the default
// `*:WARNING` clause filters it out). Guards against accidental
// regressions where the `MCINFO` macro drops the category string or
// the translator in `shekyl_log_set_categories` loses the scope.
TEST(logging, category_filter_routes_emits)
{
  mlog_set_categories("*:WARNING,net.p2p:TRACE");
  stderr_capture cap;
  ASSERT_TRUE(cap.usable())
    << "stderr_capture setup failed: " << cap.setup_error();
  MCINFO("net.p2p", "marker-net-p2p-trace");
  MCINFO("wallet.scanner", "marker-wallet-scanner-info");
  const std::string out = cap.drain();
  cap.restore();

  EXPECT_NE(out.find("marker-net-p2p-trace"), std::string::npos)
    << "net.p2p emit missing from captured stderr:\n" << out;
  EXPECT_EQ(out.find("marker-wallet-scanner-info"), std::string::npos)
    << "wallet.scanner emit leaked through a WARNING filter:\n" << out;
}

// Concurrency smoke test: two threads emit simultaneously with the
// filter open; both messages reach stderr and the test process does
// not deadlock. The easylogging++ era carried a specific
// `TEST(logging, deadlock)` regression guard for a recursive-mutex
// footgun in the old writer; the replacement property here is
// "multiple threads can emit concurrently without the subscriber
// serializing on a lock visible to the caller." `tracing`'s
// `fmt::layer` is internally lock-free at the event-construction
// layer and serializes only the final write; no external lock is
// observable.
TEST(logging, concurrent_emits_do_not_deadlock)
{
  mlog_set_categories("*:INFO");
  stderr_capture cap;
  ASSERT_TRUE(cap.usable())
    << "stderr_capture setup failed: " << cap.setup_error();

  std::thread t1([] { MGINFO("marker-concurrent-thread-1"); });
  std::thread t2([] { MGINFO("marker-concurrent-thread-2"); });
  t1.join();
  t2.join();

  const std::string out = cap.drain();
  cap.restore();

  EXPECT_NE(out.find("marker-concurrent-thread-1"), std::string::npos)
    << "thread 1 emit missing from captured stderr:\n" << out;
  EXPECT_NE(out.find("marker-concurrent-thread-2"), std::string::npos)
    << "thread 2 emit missing from captured stderr:\n" << out;
}

#endif // !_WIN32
