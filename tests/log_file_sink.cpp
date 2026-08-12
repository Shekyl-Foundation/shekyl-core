// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Regression guard for `--log-file` producing no file.
//
// `tools::on_startup()` used to call `mlog_configure("", true)`, installing the
// stderr sink before any entry point knew its log path. That was correct under
// easylogging++, where `mlog_configure` RECONFIGURED a live logger, and wrong
// under the install-once tracing subscriber underneath it, where the first
// caller wins: the daemon, the wallet and all eight `blockchain_*` tools then
// silently wrote no log file, with `--max-log-file-size` and `--max-log-files`
// inert alongside, and no diagnostic at all.
//
// WHY ITS OWN EXECUTABLE. Subscriber installation is process-global and
// happens once. A case sharing a binary with other tests would be decided by
// whichever test ran first, so the assertion would depend on link order rather
// than on the behaviour under test -- a check sharing a fate with its
// environment. Each mode below therefore needs its own process, and ctest
// gives each one its own invocation.
//
// Usage: log-file-sink-tests <file-after-on-startup|already-init-warns>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <boost/filesystem.hpp>

#include "common/util.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_log.h"

namespace bf = boost::filesystem;

namespace
{
  int fail(const std::string &why)
  {
    std::fprintf(stdout, "FAIL: %s\n", why.c_str());
    return 1;
  }

  bf::path scratch_dir()
  {
    bf::path d = bf::temp_directory_path() / bf::unique_path("shekyl-log-%%%%%%%%");
    bf::create_directories(d);
    return d;
  }

  // The behaviour the defect broke: after on_startup(), an entry point must
  // still be able to install a FILE sink. If on_startup ever initialises
  // logging again, this file never appears.
  int file_after_on_startup()
  {
    const bf::path dir = scratch_dir();
    const bf::path log = dir / "node.log";

    tools::on_startup();
    mlog_configure(log.string(), true);
    MERROR("regression probe: this line must reach the file sink");

    // The appender is NON-BLOCKING, so the file can exist and still be empty
    // when the write is checked immediately. This test read 368 bytes on one
    // run and zero on the next from identical code -- an intermittent CI red
    // that says nothing about the defect under test. `shekyl_log_shutdown`
    // drops the writer guard so the appender thread flushes, which makes the
    // assertion deterministic instead of a sleep long enough to usually work.
    shekyl_log_shutdown();

    if (!bf::exists(log))
      return fail("no log file at " + log.string() +
                  " -- logging was already initialised before mlog_configure, "
                  "so --log-file is inert");
    if (bf::file_size(log) == 0)
      return fail("log file exists but is empty at " + log.string());

    std::fprintf(stdout, "ok: file sink installed after on_startup (%s, %llu bytes)\n",
                 log.string().c_str(),
                 static_cast<unsigned long long>(bf::file_size(log)));
    return 0;
  }

  // The other half. Moving the init is not sufficient on its own: the
  // ALREADY_INIT return was classified as expected and discarded WITHOUT the
  // stderr line the surrounding comment promised the operator, so the one
  // outcome that actually occurred was the one that printed nothing. A future
  // re-introduction would then be silent for exactly the same reason.
  //
  // Silence is only correct when nothing was asked for. Here a path was passed.
  int already_init_warns()
  {
    const bf::path dir = scratch_dir();
    const bf::path log = dir / "second.log";
    const bf::path cap = dir / "stderr.txt";

    mlog_configure("", true);   // something initialises logging first

    std::fflush(stderr);
    if (!std::freopen(cap.string().c_str(), "w", stderr))
      return fail("could not redirect stderr for capture");

    mlog_configure(log.string(), true);   // and now a FILE is requested

    std::fflush(stderr);
    // Point stderr somewhere harmless again. `/dev/tty` when there is one, so a
    // failure is visible interactively; `/dev/null` under ctest, where there is
    // not. Failures are reported on STDOUT precisely so this cannot swallow
    // them. `(void)` does not suppress warn_unused_result, hence the explicit
    // branch rather than a cast.
    if (std::freopen("/dev/tty", "w", stderr) == nullptr)
    {
      if (std::freopen("/dev/null", "w", stderr) == nullptr)
        std::fprintf(stdout, "note: stderr could not be reopened; continuing\n");
    }

    std::string captured;
    if (FILE *fh = std::fopen(cap.string().c_str(), "r"))
    {
      char buf[512];
      size_t n;
      while ((n = std::fread(buf, 1, sizeof(buf), fh)) > 0)
        captured.append(buf, n);
      std::fclose(fh);
    }

    if (captured.find("NO FILE WILL BE WRITTEN") == std::string::npos)
      return fail("a log file was requested and not installed, and nothing was "
                  "printed. Captured stderr: [" + captured + "]");

    if (bf::exists(log) && bf::file_size(log) > 0)
      return fail("a second sink was installed after all; this test no longer "
                  "describes the runtime");

    std::fprintf(stdout, "ok: refused file sink announces itself on stderr\n");
    return 0;
  }
}

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    std::fprintf(stdout, "usage: %s <file-after-on-startup|already-init-warns>\n", argv[0]);
    return 2;
  }
  if (std::strcmp(argv[1], "file-after-on-startup") == 0)
    return file_after_on_startup();
  if (std::strcmp(argv[1], "already-init-warns") == 0)
    return already_init_warns();

  std::fprintf(stdout, "unknown mode %s\n", argv[1]);
  return 2;
}
