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
# Q12-R9 records what the first version of this got wrong, because both halves
# are easy to repeat:
#
#   [ -d "$DATA/lmdb" ] && mv "$DATA/lmdb" "$DATA/lmdb.pre-v9.bak"
#
#   1. The predicate tested EXISTENCE where the intent was a SCHEMA VERSION. It
#      is true whenever a daemon has ever run, so a second pass moved aside the
#      freshly built current database. On a synced chain that deletes the chain.
#   2. The safety rested on the `.bak` suffix, and the same script's `rm -rf`
#      overwrote it. Reversibility was never a property of the operation — only
#      of running it exactly once.
#
# So this script:
#
#   * asks the DAEMON for the verdict rather than parsing the schema itself. A
#     second implementation of the version check would be a duplicate free to
#     drift from the one that actually refuses; the daemon is the only oracle
#     that cannot disagree with the daemon.
#   * REFUSES ON UNKNOWN. If the probe neither starts cleanly nor emits the
#     specific pre-version refusal, nothing is touched and the exit is non-zero.
#     Guessing is exactly what the `-d` test was doing.
#   * NEVER OVERWRITES A BACKUP. The destination is timestamped and the move
#     fails if it somehow exists. Fixing the predicate alone would not have
#     saved the backups — that is an independent defect on the same line.
#
# Usage: retire_incompatible_lmdb.sh <shekyld-binary> <config-file> <data-dir>
# Exit:  0 nothing to do / retired   2 refused (unknown state, nothing touched)

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <shekyld-binary> <config-file> <data-dir>" >&2
  exit 2
fi

DAEMON="$1"; CONFIG="$2"; DATA="$3"
PROBE_SECONDS="${PROBE_SECONDS:-45}"

for f in "$DAEMON" "$CONFIG"; do
  [ -r "$f" ] || { echo "REFUSE: cannot read $f" >&2; exit 2; }
done

# `lmdb` sits under the network subdirectory the daemon chose, so find it rather
# than assuming testnet/ or mainnet/ — assuming the layout is the same class of
# error as assuming the version.
mapfile -t DBS < <(find "$DATA" -maxdepth 3 -type d -name lmdb 2>/dev/null | sort)
if [ "${#DBS[@]}" -eq 0 ]; then
  echo "OK: no chain database under $DATA — nothing to retire"
  exit 0
fi
if [ "${#DBS[@]}" -gt 1 ]; then
  echo "REFUSE: ${#DBS[@]} chain databases under $DATA; expected one:" >&2
  printf '  %s\n' "${DBS[@]}" >&2
  exit 2
fi
DB="${DBS[0]}"

# Probe with a throwaway log so the verdict cannot be confused with history from
# an earlier run.
PROBE_LOG="$(mktemp)"
trap 'rm -f "$PROBE_LOG"' EXIT
set +e
timeout "$PROBE_SECONDS" "$DAEMON" --config-file "$CONFIG" --non-interactive \
  --log-file "$PROBE_LOG" --log-level 0 >"$PROBE_LOG.stdout" 2>&1
set -e
cat "$PROBE_LOG.stdout" >> "$PROBE_LOG" 2>/dev/null || true
rm -f "$PROBE_LOG.stdout"

# The refusal text is generated from VERSION, so match the invariant part rather
# than a pinned version number: a VERSION bump must not silently stop matching.
if grep -qE "Database schema is pre-V[0-9]+; no pre-genesis migration path exists" "$PROBE_LOG"; then
  VERDICT="incompatible"
elif grep -qE "Error opening database|Failed to initialize core" "$PROBE_LOG"; then
  VERDICT="unknown-db-failure"
else
  # Started far enough to not refuse the database. Anything else that went wrong
  # is not this script's business, and is not grounds to delete a chain.
  VERDICT="compatible"
fi

case "$VERDICT" in
  compatible)
    echo "OK: daemon opens $DB — leaving it alone"
    exit 0
    ;;
  unknown-db-failure)
    echo "REFUSE: the daemon failed to open $DB, but not with the pre-version" >&2
    echo "        refusal this script knows how to act on. Nothing touched." >&2
    sed -n '1,20p' "$PROBE_LOG" >&2
    exit 2
    ;;
esac

# Timestamped, and never onto an existing path.
DEST="${DB}.retired-$(date -u +%Y%m%dT%H%M%SZ)"
if [ -e "$DEST" ]; then
  echo "REFUSE: $DEST already exists; refusing to overwrite a backup" >&2
  exit 2
fi
mv -n "$DB" "$DEST"
[ -e "$DEST" ] && [ ! -e "$DB" ] || { echo "REFUSE: move did not complete" >&2; exit 2; }

echo "RETIRED: $DB -> $DEST"
echo "         the daemon refused this schema; it will resync on next start."
echo "         Nothing is deleted — remove $DEST by hand once you are satisfied."
exit 0
