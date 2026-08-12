#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Answer one question: WILL THIS DAEMON START WITH THIS CONFIG?
#
# Pre-genesis there is no migration path — `migrate()` throws on
# `oldversion < VERSION` and tells the operator to delete the data directory and
# resync (src/blockchain_db/lmdb/db_lmdb.cpp). Provisioning needs to know which
# case it is in. It does NOT need this script to act on the answer.
#
# ---------------------------------------------------------------------------
# Why this script no longer touches the filesystem (Q12-R9)
#
# Its predecessor located, backed up and moved the database. Four review rounds
# found four defects, and all four were one mistake:
#
#   1. the database was located from a `data-dir` ARGUMENT while compatibility
#      was judged by probing with a CONFIG that carries its own `data-dir=`;
#   2. a probe timeout was read as "compatible" rather than as "still running";
#   3. `find` on an unreadable directory returns nothing, indistinguishable
#      from an empty tree;
#   4. `[ ! -e "$DATA" ]` is likewise false when a PARENT is unsearchable, so a
#      hidden database reported as a fresh node.
#
# (1) is a wrong vantage point. (2)-(4) are the caller inferring, from its own
# uid, cwd and permissions, the state of a tree the daemon opens from ITS own
# (`User=shekyl`, systemd's `WorkingDirectory`). The caller's silence was
# repeatedly taken for the daemon's absence.
#
# A fifth guard would have been a fifth chance to make the same mistake, so the
# vantage point is gone instead: this script performs NO filesystem
# introspection and NO destructive action. The daemon opens its own data
# directory with its own identity and reports what it found — the only observer
# that cannot be wrong about it. The caller decides what to do, in the open,
# where a `rm -rf` is visible in a provisioning script rather than hidden behind
# a `.bak` that proved reversible exactly once.
# ---------------------------------------------------------------------------
#
# Usage: check_chain_db_compatible.sh <shekyld-binary> <config-file>
#
# Exit:  0  usable      — the daemon ran (existing database opened, or a fresh
#                         one created). Nothing to do.
#        10 incompatible — the daemon refused the schema. The caller must clear
#                         the data directory named in <config-file> and resync.
#        2  refused     — unknown state; the caller must not guess either.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <shekyld-binary> <config-file>" >&2
  exit 2
fi

DAEMON="$1"; CONFIG="$2"
PROBE_SECONDS="${PROBE_SECONDS:-45}"

[ -x "$DAEMON" ] || { echo "REFUSE: $DAEMON is not executable" >&2; exit 2; }
[ -r "$CONFIG" ] || { echo "REFUSE: cannot read $CONFIG" >&2; exit 2; }
command -v timeout >/dev/null || { echo "REFUSE: coreutils 'timeout' not found" >&2; exit 2; }

PROBE_LOG="$(mktemp)"
trap 'rm -f "$PROBE_LOG"' EXIT
set +e
timeout "$PROBE_SECONDS" "$DAEMON" --config-file "$CONFIG" --non-interactive \
  --log-file "$PROBE_LOG" --log-level 0 >>"$PROBE_LOG" 2>&1
PROBE_RC=$?
set -e

# Classify on the exit code first: it carries what the log alone does not.
#
#   124  the timer fired, so the daemon was STILL RUNNING => it opened (or
#        created) its data directory. For a healthy node this is the EXPECTED
#        outcome, not a failure.
#   !124 it exited on its own => the log says why.
#
# Reading a timeout as "saw no refusal, therefore fine" would conflate "ran
# happily" with "died before it could say why" — defect (2) above.
if [ "$PROBE_RC" -eq 124 ]; then
  echo "USABLE: the daemon ran for ${PROBE_SECONDS}s with $CONFIG"
  exit 0
fi

# Matched on the invariant text rather than a pinned version: the message is
# generated from VERSION, so a bump must not silently stop matching.
if grep -qE "Database schema is pre-V[0-9]+; no pre-genesis migration path exists" "$PROBE_LOG"; then
  echo "INCOMPATIBLE: the daemon refuses this chain database."
  grep -oE "Database schema is pre-V[0-9]+.*" "$PROBE_LOG" | head -1 | sed 's/^/  /'
  echo "  Clear the data-dir named in $CONFIG and resync. This script will not"
  echo "  do it for you: deleting a chain is the caller's decision to make in"
  echo "  the open."
  exit 10
fi

echo "REFUSE: the daemon exited (rc=$PROBE_RC) without the pre-version refusal" >&2
echo "        this script knows how to classify. Draw no conclusion." >&2
grep -iE "error|exception|failed" "$PROBE_LOG" | head -5 >&2 || true
exit 2
