#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# No tor this lane launched survives the run (the reap/shutdown guarantee the
# live tests exist for). Used by tor-pin-verify after each crate's live tests.
#
# Usage: check_no_orphan_tor.sh <path to the staged tor executable>
#
# A process counts only if it runs THIS executable, so neither an unrelated
# tor on the runner nor a shell that merely names the path can trip it:
#
#   * Linux and macOS: its command line starts with the path (`pgrep -f`
#     matches the whole command line, so the pattern is anchored and ends at
#     the space before tor's arguments).
#   * Windows: its image path, from the process list, is the path. Git's bash
#     has no pgrep, and a command-line match would see the path as Windows
#     writes it, not as bash does.
#
# The supervisor awaits the reap, but the process table can lag a beat, so a
# bounded settle comes before the verdict. The verdict is this script's exit
# status: 0 = no survivor, 1 = one is still running (listed).

# No bash pipeline carries a verdict here (the `|` are inside PowerShell's
# script); pipefail is set so that one added later cannot lose its status.
set -u -o pipefail

exe="${1:?usage: check_no_orphan_tor.sh <tor executable>}"

if [ "${RUNNER_OS:-}" = Windows ] || [ "${OS:-}" = Windows_NT ]; then
  ORPHAN_EXE="$(cygpath -w "$exe")"
  export ORPHAN_EXE
  survivors() {
    # Exit 1 and list the survivors when one runs the executable; 0 when none.
    powershell -NoProfile -NonInteractive -Command '
      $found = @(Get-Process -Name tor -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -ieq $env:ORPHAN_EXE })
      if ($found.Count -gt 0) { $found | Format-Table Id, Path -AutoSize | Out-String | Write-Output; exit 1 }
      exit 0'
  }
else
  survivors() {
    if pgrep -af "^$exe "; then
      return 1
    fi
    return 0
  }
fi

for _ in 1 2 3 4 5; do
  if survivors > /dev/null; then
    exit 0
  fi
  sleep 1
done
echo "a tor launched by this lane outlived its test run:" >&2
survivors
exit 1
