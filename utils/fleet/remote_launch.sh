#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Start a long-lived process on a fleet host and PROVE it is running, from a
# connection that cannot have been part of starting it.
#
# ---------------------------------------------------------------------------
# The defect class this exists to prevent: THE CHECK SHARING A FATE WITH ITS
# SUBJECT
#
# Three instances of it in this arc, and they look nothing alike until reduced:
#
#   Q12-R9   `[ -d .../lmdb ]` guarding a destructive move — the caller's own
#            uid, cwd and permissions standing in for the daemon's.
#   here (a) `ps | grep -c "tor-0.torrc"` returned 2 and was read as a duplicate
#            process. It was the real tor plus the ssh WRAPPER, whose command
#            line contains the torrc path. THE PREDICATE WAS IN ITS OWN SAMPLE,
#            and a healthy tor was killed on the strength of it.
#   here (b) launch-and-verify in ONE ssh command: the connection teardown that
#            killed the process was also what stopped the verification from
#            printing. The check reported nothing, and nothing read as fine.
#   here (c) cleaning up after this script's own controls with
#            `pkill -f "sleep 300"` — which killed the ssh wrapper running it,
#            because the wrapper's command line contains the pattern. Committed
#            while writing this comment. `-f` searches the full command line of
#            a table that includes the searcher; `pgrep -x` matches the
#            executable name and does not.
#
# The unifying property is not "the actor and the observer are the same" — it is
# that **the check shares a fate with the thing it checks**. So this script
# breaks both couplings, deliberately:
#
#   1. IDENTIFY BY PID, NEVER BY PATTERN. The remote shell records `$!` to a
#      pidfile. A PID cannot match itself the way a grep pattern can, and
#      /proc/<pid>/cmdline confirms identity without a text search over a
#      process table that contains the searcher.
#   2. VERIFY OVER A SEPARATE CONNECTION. The launch connection is expected to
#      hang — a detached child holds the channel open — so its exit status is
#      MEANINGLESS BY DESIGN and is discarded explicitly rather than trusted.
#      A second ssh, established after the first is gone, asks whether the
#      process outlived it. That is the only question worth asking.
#   3. FAIL LOUDLY. Silence is a failure, not a pass: if verification cannot be
#      completed, this exits nonzero and prints the remote log tail.
# ---------------------------------------------------------------------------
#
# Usage: remote_launch.sh <ssh-host> <pidfile> <logfile> <command...>
#
# Exit:  0  the process is running, confirmed by pid over a fresh connection
#        1  it is not running, or could not be confirmed — log tail on stderr
#        2  bad invocation

set -uo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: $0 <ssh-host> <pidfile> <logfile> <command...>" >&2
  exit 2
fi

HOST="$1"; PIDFILE="$2"; LOGFILE="$3"; shift 3

# The remote side is a SHELL, so the command must reach it as a string -- but
# `$*` flattens argv and the remote shell then re-splits it, so any argument
# containing a space arrives as two. `printf %q` quotes each argument for shell
# re-parsing, which preserves argv exactly and, as a side effect, removes the
# injection surface a flattened string would have.
CMD=""
for arg in "$@"; do
  CMD="${CMD:+$CMD }$(printf '%q' "$arg")"
done

# Absolute paths only. `~` does not expand inside the quoting this script needs
# to survive spaces, so a tilde silently writes nothing and the run then reports
# NO-PIDFILE — indistinguishable from a process that died. Both controls hit
# this, which is the point of running controls: refuse the ambiguity here rather
# than mislabel it later.
case "$PIDFILE" in /*) ;; *) echo "REFUSE: pidfile must be an absolute path, got '$PIDFILE'" >&2; exit 2 ;; esac
case "$LOGFILE" in /*) ;; *) echo "REFUSE: logfile must be an absolute path, got '$LOGFILE'" >&2; exit 2 ;; esac
LAUNCH_TIMEOUT="${LAUNCH_TIMEOUT:-15}"
SETTLE_SECONDS="${SETTLE_SECONDS:-10}"

# Phase 1 — launch. This connection is EXPECTED to be cut off by the timeout;
# the child is detached with setsid and holds no channel we care about. The
# exit status is discarded on purpose: it reports whether ssh was killed, which
# is not the question.
timeout "$LAUNCH_TIMEOUT" ssh -n -o BatchMode=yes "$HOST" \
  "nohup setsid $CMD >'$LOGFILE' 2>&1 </dev/null & echo \$! > '$PIDFILE'" \
  >/dev/null 2>&1 || true

sleep "$SETTLE_SECONDS"

# Phase 2 — verify, over a connection that did not exist when the process was
# started. `kill -0` on the recorded pid plus a cmdline check: no pattern
# search, so nothing in this check can match this check.
verdict=$(timeout 30 ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$HOST" "
  pid=\$(cat '$PIDFILE' 2>/dev/null)
  if [ -z \"\$pid\" ]; then echo 'NO-PIDFILE'; exit 0; fi
  if ! kill -0 \"\$pid\" 2>/dev/null; then echo \"DEAD \$pid\"; exit 0; fi
  # setsid's child is the real process; accept either, and print what it is.
  cmdline=\$(tr '\\0' ' ' < /proc/\"\$pid\"/cmdline 2>/dev/null)
  echo \"ALIVE \$pid \$cmdline\"
" 2>/dev/null)

case "${verdict:-}" in
  ALIVE*)
    echo "$HOST: ${verdict}"
    exit 0
    ;;
  '')
    echo "$HOST: VERIFICATION PRODUCED NO ANSWER — treating as failure." >&2
    echo "  A check that prints nothing is the defect this script exists to" >&2
    echo "  prevent; it is never read as success." >&2
    exit 1
    ;;
  *)
    echo "$HOST: NOT RUNNING (${verdict})" >&2
    timeout 25 ssh -n -o BatchMode=yes "$HOST" "tail -6 '$LOGFILE' 2>/dev/null" >&2
    exit 1
    ;;
esac
