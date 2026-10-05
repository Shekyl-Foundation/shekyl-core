#!/usr/bin/env bash
# Drive `open_edge` (WSS-Q1(b), WSS_Q1B_BENCH_SPEC.md §4) against a live
# `shekyld --regtest`.
#
# Get the mining address from the deterministic regtest wallet:
#
#   SHEKYLD_BIN=<path> cargo test --release -p shekyl-engine-core --lib \
#     regtest_daemon_spawns_and_mines_to_wallet_address -- --ignored --nocapture
#
# which prints `wallet address: ...` and validates the daemon binary on the way.
#
# KNOWN LIMIT, and it is the reason this script is not a grading instrument:
# blocks mined this way are COINBASE-ONLY, so the fetch makes two round trips
# per block instead of three and each block carries ~1.4 kB. The volume term is
# therefore untested rather than measured -- see the FOLLOWUPS row.
#
# Exit status is `open_edge`'s, unpiped (46-shell-gate-exits).
set -u
WT="${WT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SCRATCH="${SCRATCH:-${TMPDIR:-/tmp}/wss-q1b}"
mkdir -p "$SCRATCH"
BIN="${SHEKYLD_BIN:-$WT/build/bin/shekyld}"
PORT="${PORT:-28591}"
DATA="${DATA:-${TMPDIR:-/tmp}/skl-oe-run}"
ADDR="${1:?usage: wss_q1b_regtest_open_edge.sh <mining-address> [blocks]}"
BLOCKS="${2:-40}"
# The sample is derived from what was mined, not fixed: the fetch used to start
# at height 1 and always take 30, so `blocks=20` mined 20 and then failed
# fetching heights 21-30 -- an argument the script accepted and did not honour.
# One block is held back because height 0 is genesis and the mined range ends at
# $BLOCKS.
SAMPLE=$(( BLOCKS < 30 ? BLOCKS : 30 ))
if [ "$BLOCKS" -lt 2 ]; then
  echo "blocks must be at least 2 (one genesis, one sampled); got $BLOCKS"; exit 7
fi

rm -rf "$DATA"; mkdir -p "$DATA"
# The daemon exits on stdin EOF (its own log says so: "EOF on stdin, exiting"),
# which is why the Rust harness gives it a piped stdin and holds the handle.
# A background job inherits the script's stdin, so `< /dev/null` -- or a closed
# pipe -- kills it the moment it starts. A FIFO held open on fd 3 is the shell
# equivalent of holding the pipe.
FIFO="$DATA/stdin.fifo"
mkfifo "$FIFO"
exec 3<>"$FIFO"
"$BIN" --regtest --offline --no-igd --fixed-difficulty 1 \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port "$PORT" \
  --data-dir "$DATA" --log-level 1 <&3 > "$DATA/daemon.out" 2>&1 &
DPID=$!
echo "daemon pid $DPID, port $PORT"

# Wait for RPC readiness rather than sleeping a guessed interval.
#
# No pipe: `curl ... | grep -q` would put an EARLY-EXIT consumer on the end of
# the pipeline, which is the SIGPIPE trap 46-shell-gate-exits names, and the
# verdict that matters (did the daemon answer?) would travel through it. The
# reply is captured and tested in the shell instead.
for _ in $(seq 1 60); do
  REPLY_BODY=$(curl -s -m 2 -X POST "http://127.0.0.1:$PORT/json_rpc" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}')
  case "$REPLY_BODY" in
    *'"status"'*) READY=1; break ;;
  esac
  sleep 2
done
if [ "${READY:-0}" != 1 ]; then
  echo "daemon never became ready; tail of its log:"; tail -20 "$DATA/daemon.out"
  kill -9 "$DPID" 2>/dev/null; exit 9
fi
echo "daemon ready"

curl -s -m 60 -X POST "http://127.0.0.1:$PORT/json_rpc" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"generateblocks\",\"params\":{\"amount_of_blocks\":$BLOCKS,\"wallet_address\":\"$ADDR\",\"starting_nonce\":0}}" \
  > "$SCRATCH/generate.json" 2>&1
python3 - "$SCRATCH/generate.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
if "error" in d: print("generateblocks ERROR:", d["error"]); sys.exit(1)
r=d.get("result",{}); print("mined to height", r.get("height"), "blocks", len(r.get("blocks") or []))
PY
GEN=$?
if [ "$GEN" -ne 0 ]; then kill -9 "$DPID" 2>/dev/null; exit 8; fi

"${OPEN_EDGE:-$WT/rust/target/release/open_edge}" --daemon "http://127.0.0.1:$PORT" \
  --blocks "$SAMPLE" --from-height 1 --floor-samples 50 \
  --json "$SCRATCH/openedge.json"
RC=$?
kill -9 "$DPID" 2>/dev/null
echo "open_edge exit=$RC"
exit "$RC"
