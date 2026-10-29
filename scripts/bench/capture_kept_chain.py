#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Open one kept regtest datadir, capture the RPC column, stop the daemon.

import json
import os
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc_capture as C  # noqa: E402


def main():
    daemon, data, out, tx = sys.argv[1:5]
    if tx == "-":
        tx = None
    port = 38141
    log = os.path.join(out, "daemon.log")
    os.makedirs(out, exist_ok=True)
    proc = subprocess.Popen(
        [daemon, "--network", "regtest", "--data-dir", data, "--log-file", log,
         "--clearnet", "off", "--tor", "off", "--p2p-local", "--dev-rpc",
         "--rpc-admin-listen", f"127.0.0.1:{port}",
         "--rpc-view-listen", "127.0.0.1:38142"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    info = None
    try:
        for _ in range(60):
            try:
                req = urllib.request.Request(
                    url + "/json_rpc",
                    data=json.dumps({"jsonrpc": "2.0", "id": "0", "method": "get_info"}).encode(),
                    headers={"Content-Type": "application/json"})
                info = json.loads(urllib.request.urlopen(req, timeout=3).read())
                if info.get("result", {}).get("status") == "OK":
                    break
            except (OSError, json.JSONDecodeError, urllib.error.URLError):
                info = None
            time.sleep(1)
        else:
            raise SystemExit("get_info never came up")
        result = info["result"]
        height = result["height"]
        tip = result["top_block_hash"]
        hdr_req = urllib.request.Request(
            url + "/json_rpc",
            data=json.dumps({
                "jsonrpc": "2.0", "id": "0", "method": "get_block_header_by_height",
                "params": {"height": 0}}).encode(),
            headers={"Content-Type": "application/json"})
        genesis = json.loads(urllib.request.urlopen(hdr_req, timeout=10).read())
        genesis_hash = genesis["result"]["block_header"]["hash"]
        requests = C.chain_requests(height, tip, genesis_hash, tx)
        with open(os.path.join(out, "requests.json"), "w", encoding="utf-8") as fh:
            json.dump(requests, fh, indent=2)
            fh.write("\n")
        n = C.capture(url, requests, os.path.join(out, "replies"))
        record = {
            "datadir": data,
            "get_info_height": height,
            "top_block_hash": tip,
            "genesis_hash": genesis_hash,
            "tx_hash": tx,
            "version": result.get("version"),
            "replies": n,
        }
        with open(os.path.join(out, "tip.json"), "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        print(json.dumps(record))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
