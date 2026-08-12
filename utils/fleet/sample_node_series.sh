#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# The arm's measurement: a PER-NODE TIME SERIES over both readout series, and
# the fraction of wall-clock each node spends at or above the outbound floor.
#
# ---------------------------------------------------------------------------
# Why a fraction and not a verdict
#
# At the arm's `A` the outbound target and the floor are the same number, so a
# healthy node sits exactly ON its own trigger with no headroom. Any transient
# loss of one peer drops it below, stops its anonymity stemming, and it
# recovers when the peer returns -- the stem FLAPS rather than being on or off.
# "Floor reached: yes/no" is then a point observation of a quantity that
# oscillates around the threshold, and two nodes with the same verdict can be
# materially different networks. A node holding the floor 99% of the time and
# one holding it 60% of the time are not the same launch condition.
#
# A fleet total cannot carry this either: it cannot distinguish one node steady
# at 20 from one oscillating across the floor, and the floor is per node.
# ---------------------------------------------------------------------------
#
# The floor is DERIVED, not typed in here. `MIN_PROVISIONED_OUT_PEERS` in
# rust/shekyl-relay-privacy/src/params.rs is the single owner, and that file
# records what happened the last time this number was mirrored by hand: five
# copies, no owner, and nothing that failed when the daemon's value moved --
# instruments reporting numbers for a network that does not exist. So it is
# read from the source, and a rename or a move REFUSES rather than falling back
# to a remembered 12.
#
# Usage: sample_node_series.sh <inventory-file> <out-dir>
#
#   N      samples to take (default 12)
#   GAP    seconds between samples (default 240)
#   FLOOR  override the derived floor (stated in the report when used)
#
# Writes <out-dir>/series.tsv (raw, append-only) and prints the summary.
#
# Exit:  0  every sample was complete
#        1  at least one sample was short -- the series has holes
#        2  bad invocation

set -uo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <inventory-file> <out-dir>" >&2
  exit 2
fi

INVENTORY="$1"; OUTDIR="$2"
[ -r "$INVENTORY" ] || { echo "REFUSE: cannot read $INVENTORY" >&2; exit 2; }
mkdir -p "$OUTDIR" || { echo "REFUSE: cannot create $OUTDIR" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
READER="$SCRIPT_DIR/read_anon_histogram.sh"
[ -r "$READER" ] || { echo "REFUSE: read_anon_histogram.sh not found next to this script" >&2; exit 2; }

N="${N:-12}"; GAP="${GAP:-240}"
case "$N"   in ''|*[!0-9]*) echo "REFUSE: N '$N' is not a number" >&2; exit 2 ;; esac
case "$GAP" in ''|*[!0-9]*) echo "REFUSE: GAP '$GAP' is not a number" >&2; exit 2 ;; esac
[ "$N" -ge 1 ] || { echo "REFUSE: N must be at least 1" >&2; exit 2; }

# The number of nodes is pinned from the inventory, so a short reading is a
# refusal rather than a plausible-looking row with fewer values than nodes.
EXPECT_NODES=$(grep -cvE '^[[:space:]]*#|^[[:space:]]*$' "$INVENTORY")
[ "$EXPECT_NODES" -ge 1 ] || { echo "REFUSE: inventory lists no nodes" >&2; exit 2; }

PARAMS="$SCRIPT_DIR/../../rust/shekyl-relay-privacy/src/params.rs"
if [ -n "${FLOOR:-}" ]; then
  case "$FLOOR" in ''|*[!0-9]*) echo "REFUSE: FLOOR '$FLOOR' is not a number" >&2; exit 2 ;; esac
  FLOOR_SRC="overridden by FLOOR=$FLOOR"
else
  [ -r "$PARAMS" ] || {
    echo "REFUSE: cannot read $PARAMS to derive the floor." >&2
    echo "        Set FLOOR= explicitly rather than letting this default to a" >&2
    echo "        number nothing owns." >&2; exit 2; }
  FLOOR=$(sed -n 's/^pub const MIN_PROVISIONED_OUT_PEERS: u32 = \([0-9]\+\);.*/\1/p' "$PARAMS")
  case "${FLOOR:-}" in ''|*[!0-9]*)
    echo "REFUSE: MIN_PROVISIONED_OUT_PEERS not found in params.rs." >&2
    echo "        It was renamed, moved, or changed shape. Refusing rather than" >&2
    echo "        measuring against a floor this script remembers." >&2; exit 2 ;;
  esac
  FLOOR_SRC="derived from MIN_PROVISIONED_OUT_PEERS in params.rs"
fi

RAW="$OUTDIR/series.tsv"
short=0

echo "sampling $EXPECT_NODES node(s), N=$N GAP=${GAP}s, floor=$FLOOR ($FLOOR_SRC)"
echo "raw -> $RAW"
echo

for i in $(seq 1 "$N"); do
  ts=$(date -u +%H:%M:%S)
  out=$(bash "$READER" --tsv "$INVENTORY" 2>/dev/null)
  read_n=$(printf '%s\n' "$out" | awk -F'\t' '$1=="END"{print $2}')
  fail_n=$(printf '%s\n' "$out" | awk -F'\t' '$1=="END"{print $3}')

  # `END` is why this is a check and not an inference: a consumer counting rows
  # cannot tell a short reading from a complete one.
  if [ "${read_n:-}" != "$EXPECT_NODES" ] || [ "${fail_n:-1}" != "0" ]; then
    printf '%s  SHORT: %s/%s node(s) read, %s failed -- sample discarded\n' \
      "$ts" "${read_n:-?}" "$EXPECT_NODES" "${fail_n:-?}"
    short=$((short + 1))
  else
    printf '%s\n' "$out" | awk -F'\t' -v s="$i" -v t="$ts" \
      '$1=="NODE"{printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s, t, $2, $3, $4, $6, $7}' >> "$RAW"
    printf '%s  sample %s/%s ok  links=[%s]  stored=[%s]\n' "$ts" "$i" "$N" \
      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="NODE"{printf "%s%s", sep, $3; sep=","}')" \
      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="NODE"{printf "%s%s", sep, $6; sep=","}')"
  fi
  [ "$i" -lt "$N" ] && sleep "$GAP"
done

echo
if [ ! -s "$RAW" ]; then
  echo "REFUSE: no complete samples; there is no series to summarise" >&2
  exit 1
fi

echo "per-node summary (floor = $FLOOR)"
awk -F'\t' -v floor="$FLOOR" '
  { n[$3]++; if ($4 >= floor) up[$3]++
    if (!($3 in lo) || $4 < lo[$3]) lo[$3] = $4
    if (!($3 in hi) || $4 > hi[$3]) hi[$3] = $4
    if (!($3 in slo) || $6 < slo[$3]) slo[$3] = $6
    sum[$3] += $4 }
  END {
    printf "  %-8s %7s %7s %9s %9s %s\n", "node", "min", "max", "mean", "stored", "at-or-above-floor"
    for (k in n) {
      f = (k in up) ? up[k] / n[k] * 100 : 0
      printf "  %-8s %7d %7d %9.2f %9d %8.1f%%  (%d/%d)\n", \
        k, lo[k], hi[k], sum[k] / n[k], slo[k], f, (k in up) ? up[k] : 0, n[k]
    }
  }' "$RAW" | { IFS= read -r hdr; printf '%s\n' "$hdr"; sort; }

echo
awk -F'\t' -v floor="$FLOOR" '
  { n++; if ($4 >= floor) up++ }
  END { printf "  fleet: %.1f%% of node-samples at or above the floor (%d/%d)\n",
          (n ? up / n * 100 : 0), up, n }' "$RAW"

if [ "$short" -gt 0 ]; then
  echo >&2
  echo "INCOMPLETE: $short of $N samples were short and were DISCARDED, not" >&2
  echo "backfilled. The fractions above are over the samples that survived, so" >&2
  echo "they describe a series with holes in it." >&2
  exit 1
fi
