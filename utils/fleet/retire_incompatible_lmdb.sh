#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Retire a chain database the current daemon refuses to open — and refuse to do
# anything else.
#
# Pre-genesis there is no migration path: `migrate()` throws on
# `oldversion < VERSION` and tells the operator to delete and resync
# (src/blockchain_db/lmdb/db_lmdb.cpp). Provisioning therefore needs a step that
# retires an incompatible database, and that step is destructive.
#
# Q12-R9 records what earlier versions got wrong. Each is easy to repeat:
#
#   1. `[ -d "$DATA/lmdb" ]` tested EXISTENCE where the intent was a SCHEMA
#      VERSION — true whenever a daemon had ever run, so a second pass moved
#      aside the freshly built current database.
#   2. Safety rested on a `.bak` suffix that the same script's `rm -rf`
#      overwrote, so reversibility was a property of running it once, not of
#      the operation.
#   3. The database was located from a data-dir ARGUMENT while compatibility
#      was judged by probing with a CONFIG FILE that carries its own
#      `data-dir=`. Nothing tied them together, so the probe could refuse one
#      tree while the move retired another — including a current-schema chain.
#      That is the same defect as (1) wearing a different costume: a
#      destructive operation whose guard does not look at its own subject.
#
# (3) is fixed by REMOVING THE SECOND SOURCE rather than by checking the two
# agree: the config's `data-dir` is the single authority, so the probe and the
# move cannot disagree about what they are talking about.
#
# Usage: retire_incompatible_lmdb.sh <shekyld-binary> <config-file>
# Exit:  0 nothing to do / retired   2 refused (unknown state, nothing touched)

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

# The config is the ONLY source for the data directory. Refuse rather than
# guess a default: guessing is what every defect above had in common.
DATA=$(sed -n 's/^[[:space:]]*data-dir[[:space:]]*=[[:space:]]*//p' "$CONFIG" | tail -1)
[ -n "$DATA" ] || { echo "REFUSE: $CONFIG sets no data-dir; refusing to guess one" >&2; exit 2; }

mapfile -t DBS < <(find "$DATA" -maxdepth 3 -type d -name lmdb 2>/dev/null | sort)
if [ "${#DBS[@]}" -eq 0 ]; then
  echo "OK: no chain database under $DATA (from $CONFIG) — nothing to retire"
  exit 0
fi
if [ "${#DBS[@]}" -gt 1 ]; then
  echo "REFUSE: ${#DBS[@]} chain databases under $DATA; expected one:" >&2
  printf '  %s\n' "${DBS[@]}" >&2
  exit 2
fi
DB="${DBS[0]}"

PROBE_LOG="$(mktemp)"
trap 'rm -f "$PROBE_LOG"' EXIT
set +e
timeout "$PROBE_SECONDS" "$DAEMON" --config-file "$CONFIG" --non-interactive \
  --log-file "$PROBE_LOG" --log-level 0 >>"$PROBE_LOG" 2>&1
PROBE_RC=$?
set -e

# The exit code carries information the log alone does not, so classify on both.
#
#   124  timeout fired => the daemon was STILL RUNNING => it opened the database.
#        For a healthy chain this is the EXPECTED outcome, not a failure.
#   !124 the daemon exited on its own => read the log to find out why.
#
# Treating a timeout as "no refusal seen, therefore fine" would conflate "ran
# happily" with "died before it could say why".
if [ "$PROBE_RC" -eq 124 ]; then
  VERDICT="compatible"
elif grep -qE "Database schema is pre-V[0-9]+; no pre-genesis migration path exists" "$PROBE_LOG"; then
  # Matched on the invariant text rather than a pinned version: the message is
  # generated from VERSION, so a bump must not silently stop matching.
  VERDICT="incompatible"
else
  VERDICT="unknown"
fi

case "$VERDICT" in
  compatible)
    echo "OK: daemon ran with $DB (probe reached its ${PROBE_SECONDS}s timeout) — leaving it alone"
    exit 0
    ;;
  unknown)
    echo "REFUSE: the daemon exited (rc=$PROBE_RC) without the pre-version refusal" >&2
    echo "        this script knows how to act on. Nothing touched." >&2
    grep -iE "error|exception|failed" "$PROBE_LOG" | head -5 >&2 || true
    exit 2
    ;;
esac

DEST="${DB}.retired-$(date -u +%Y%m%dT%H%M%SZ)"
[ -e "$DEST" ] && { echo "REFUSE: $DEST exists; refusing to overwrite a backup" >&2; exit 2; }
mv -n "$DB" "$DEST"
# `mv -n` is silent when it declines, so assert the move rather than trust it.
[ -e "$DEST" ] && [ ! -e "$DB" ] || { echo "REFUSE: move did not complete" >&2; exit 2; }

echo "RETIRED: $DB -> $DEST"
echo "         the daemon refused this schema; it will resync on next start."
echo "         Nothing is deleted — remove $DEST by hand once you are satisfied."
exit 0
