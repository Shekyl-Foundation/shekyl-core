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
#   * Linux and macOS: its command line is the path, or starts with the path
#     and a space (tor's arguments follow). The comparison is of strings, not
#     a pattern, so a path holding `.`, `+` or brackets means only itself.
#   * Windows: its image path, from the process list, is the path. Git's bash
#     has no pgrep, and a command-line match would see the path as Windows
#     writes it, not as bash does.
#
# Either way the process list is read whole first, and must show the process
# reading it: a list that could not be read, or that cannot see its reader,
# is no evidence that nothing survived (rule 47), so it is exit 2.
#
# The supervisor awaits the reap, but the process table can lag a beat, so a
# bounded settle comes before the verdict. The verdict is this script's exit
# status: 0 = no survivor, 1 = one is still running (listed), 2 = the process
# list could not be judged.

# No bash pipeline carries a verdict here (the `|` are inside PowerShell's
# script); pipefail is set so that one added later cannot lose its status.
set -u -o pipefail

exe="${1:?usage: check_no_orphan_tor.sh <tor executable>}"

if [ "${RUNNER_OS:-}" = Windows ] || [ "${OS:-}" = Windows_NT ]; then
  ORPHAN_EXE="$(cygpath -w "$exe")"
  export ORPHAN_EXE
  survivors() {
    powershell -NoProfile -NonInteractive -Command '
      try { $all = @(Get-Process -ErrorAction Stop) } catch { exit 2 }
      if (-not ($all | Where-Object { $_.Id -eq $PID })) { exit 2 }
      $found = @($all | Where-Object { $_.Name -eq "tor" -and $_.Path -ieq $env:ORPHAN_EXE })
      if ($found.Count -gt 0) { $found | Format-Table Id, Path -AutoSize | Out-String | Write-Output; exit 1 }
      exit 0'
  }
else
  survivors() {
    local listing pid args found=0 seen_self=0
    if ! listing="$(ps -A -o pid= -o args=)"; then
      return 2
    fi
    while read -r pid args; do
      if [ "$pid" = "$$" ]; then
        seen_self=1
      fi
      if [ "$args" = "$exe" ] || [[ "$args" == "$exe "* ]]; then
        printf '%s %s\n' "$pid" "$args"
        found=1
      fi
    done <<< "$listing"
    if [ "$seen_self" -eq 0 ]; then
      return 2
    fi
    return "$found"
  }
fi

for _ in 1 2 3 4 5; do
  survivors > /dev/null
  rc=$?
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  if [ "$rc" -ne 1 ]; then
    echo "check_no_orphan_tor: the process list could not be read, or does not show its reader" >&2
    exit 2
  fi
  sleep 1
done
echo "a tor launched by this lane outlived its test run:" >&2
survivors
exit 1
