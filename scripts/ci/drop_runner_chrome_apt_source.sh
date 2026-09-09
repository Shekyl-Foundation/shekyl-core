#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Drop Google Chrome apt sources the GitHub ubuntu image ships.
#
# A hash-sum mismatch on dl.google.com/linux/chrome is not any job's
# subject (ripgrep, valgrind, libssl, …) and has failed apt-get update
# before the job ran (PR #671, 2026-09-09). Naming google-chrome.list
# and .list.save left .sources and google.list live: apt still fetched
# chrome and returned 100. Delete every chrome source, then assert the
# URI is gone so a renamed file cannot fail the next job silently.

set -euo pipefail

if [ -d /etc/apt/sources.list.d ]; then
  sudo find /etc/apt/sources.list.d -maxdepth 1 -iname '*chrome*' -delete
  shopt -s nullglob
  for f in /etc/apt/sources.list.d/*; do
    [ -f "$f" ] || continue
    if grep -q 'dl.google.com/linux/chrome' "$f"; then
      sudo rm -f "$f"
    fi
  done
fi

# Rule 47: a green drop that left a chrome URI in place is vacuous.
# Absence of chrome on a future image is success (nothing to drop);
# a remaining URI is the drop missing its subject.
if grep -Rqs 'dl.google.com/linux/chrome' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  echo "FATAL: chrome apt source still present after drop:" >&2
  grep -Rn 'dl.google.com/linux/chrome' /etc/apt/sources.list /etc/apt/sources.list.d >&2 || true
  exit 1
fi
