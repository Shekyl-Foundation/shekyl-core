#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Open one kept regtest datadir, capture the RPC column, stop the daemon.
#
# The datadir is produced by
# `engine::regtest_e2e::capture_chain_keeps_its_datadir` (`#[ignore]`,
# `SHEKYLD_BIN` set). That test keeps the directory when the daemon is
# dropped. This tool opens it, writes one reply file per chain read, and
# stops the daemon.
#
# stdout and stderr go to `console.log` under the output directory. A
# bind failure or a datadir the binary will not open is in that file.

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc_capture as C  # noqa: E402

# The column talks to the admin listener. View listen defaults to none
# and is not bound.
ADMIN_LISTENER_COUNT = 1

READY_TIMEOUT_S = 60
READY_POLL_S = 1
PROBE_TIMEOUT_S = 3
GENESIS_TIMEOUT_S = 10
STOP_TIMEOUT_S = 20

# `get_info.height` of a chain that holds its genesis block and nothing
# after it. The column refuses a height below this.
GENESIS_CHAIN_HEIGHT = 1


def _wait_ready(proc, base_url, console_log):
    """The daemon's `get_info`, or a refusal that names the console log.

    A process that has already exited is not a timeout. The log is where
    a bind failure or a datadir the binary will not open was written.
    """
    deadline = time.monotonic() + READY_TIMEOUT_S
    while time.monotonic() < deadline:
        exited = proc.poll()
        if exited is not None:
            raise SystemExit(
                f"the daemon exited {exited} before get_info; see {console_log}")
        try:
            info = C.json_rpc(base_url, "get_info", timeout=PROBE_TIMEOUT_S)
        except (OSError, urllib.error.URLError, TimeoutError):
            time.sleep(READY_POLL_S)
            continue
        result = info.get("result") if isinstance(info, dict) else None
        if isinstance(result, dict) and result.get("status") == "OK":
            return result
        time.sleep(READY_POLL_S)
    raise SystemExit(
        f"get_info did not answer within {READY_TIMEOUT_S}s; see {console_log}")


def main():
    ap = argparse.ArgumentParser(
        description="Capture the RPC column of one kept regtest datadir")
    ap.add_argument("daemon", help="shekyld binary")
    ap.add_argument("data", help="kept regtest data directory")
    ap.add_argument("out", help="directory the capture is written to")
    ap.add_argument("tx", nargs="?", default="-",
                    help="a transaction id to ask about, or '-' for none")
    args = ap.parse_args()
    tx = None if args.tx == "-" else args.tx

    # Before the daemon, the console, or requests.json. A rerun into a
    # directory that already holds replies would otherwise start a node
    # and then be refused by the capture, having already overwritten the
    # previous run's request list.
    replies_dir = os.path.join(args.out, "replies")
    occupied = C.occupied_replies_refusal(replies_dir)
    if occupied:
        raise SystemExit(occupied)

    os.makedirs(args.out, exist_ok=True)
    console_log = os.path.join(args.out, "console.log")
    daemon_log = os.path.join(args.out, "daemon.log")
    ports, held = C.reserve_loopback_ports(ADMIN_LISTENER_COUNT)
    for sk in held:
        sk.close()
    admin_port = ports[0]
    base_url = f"http://127.0.0.1:{admin_port}"

    console = open(console_log, "w", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            [args.daemon, "--network", "regtest", "--data-dir", args.data,
             "--log-file", daemon_log, "--clearnet", "off", "--tor", "off",
             "--p2p-local", "--dev-rpc",
             "--rpc-admin-listen", f"127.0.0.1:{admin_port}"],
            stdout=console, stderr=subprocess.STDOUT)
    finally:
        console.close()

    try:
        result = _wait_ready(proc, base_url, console_log)
        height = result["height"]
        if not isinstance(height, int) or isinstance(height, bool) \
                or height < GENESIS_CHAIN_HEIGHT:
            raise SystemExit(
                f"get_info height {height!r} is not a chain; see {console_log}")
        tip = result["top_block_hash"]
        genesis = C.json_rpc(
            base_url, "get_block_header_by_height", {"height": 0},
            timeout=GENESIS_TIMEOUT_S)
        genesis_hash = genesis["result"]["block_header"]["hash"]
        requests = C.chain_requests(height, tip, genesis_hash, tx)
        with open(os.path.join(args.out, "requests.json"), "w", encoding="utf-8") as fh:
            json.dump(requests, fh, indent=2)
            fh.write("\n")
        n = C.capture(base_url, requests, replies_dir)
        record = {
            "datadir": args.data,
            "get_info_height": height,
            "top_block_hash": tip,
            "genesis_hash": genesis_hash,
            "tx_hash": tx,
            "version": result.get("version"),
            "replies": n,
        }
        with open(os.path.join(args.out, "tip.json"), "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        print(json.dumps(record))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
