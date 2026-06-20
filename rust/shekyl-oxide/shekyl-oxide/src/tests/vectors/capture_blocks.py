#!/usr/bin/env python3
"""Oracle-emit: capture raw coinbase block blobs from a throwaway regtest shekyld.

Writes regtest_coinbase_h{0,1,2}.block (raw bytes) next to this script. The C++
block serializer is the genesis wire-format oracle; these blobs feed the
`Block::read` -> `Block::serialize` byte-identity KAT in `../block.rs`.

Usage:  python3 capture_blocks.py   [SHEKYLD_BIN env overrides the daemon path]
"""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# repo root = .../shekyl-core (this file is rust/shekyl-oxide/shekyl-oxide/src/tests/vectors/)
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", ".."))
BIN = os.environ.get("SHEKYLD_BIN", os.path.join(ROOT, "build", "bin", "shekyld"))
GENESIS_RECIPIENTS = os.path.abspath(os.path.join(
    ROOT, "..", "shekyl-dev", "tools", "genesis_builder",
    "genesis_recipients.mainnet.json"))
N_BLOCKS = 5
CAPTURE_HEIGHTS = [0, 1, 2]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Daemon:
    def __init__(self, port):
        self.port = port
        self.url = f"http://127.0.0.1:{port}/json_rpc"
        self.workdir = tempfile.mkdtemp(prefix="wirecap_")
        self.proc = None
        self.log = open(os.path.join(self.workdir, "daemon.log"), "w")

    def start(self):
        self.proc = subprocess.Popen(
            [BIN, "--regtest", "--offline", "--non-interactive",
             "--fixed-difficulty", "1", "--data-dir", self.workdir,
             "--rpc-bind-port", str(self.port), "--log-level", "0"],
            stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(120):
            try:
                if self.rpc("get_info").get("status") == "OK":
                    return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("daemon RPC not ready; see " + self.workdir)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()

    def rpc(self, method, params=None):
        body = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            body["params"] = params
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read())
        if "error" in res:
            raise RuntimeError(f"{method} -> {res['error']}")
        return res["result"]


def main():
    addr = json.loads(open(GENESIS_RECIPIENTS).read())["recipients"][0]["address"]
    d = Daemon(free_port())
    print(f"spawning {BIN} on port {d.port}", file=sys.stderr)
    d.start()
    try:
        d.rpc("generateblocks", {"amount_of_blocks": N_BLOCKS, "wallet_address": addr})
        h = d.rpc("get_info")["height"]
        for height in CAPTURE_HEIGHTS:
            if height >= h:
                continue
            blob = bytes.fromhex(d.rpc("get_block", {"height": height})["blob"])
            out = os.path.join(HERE, f"regtest_coinbase_h{height}.block")
            open(out, "wb").write(blob)
            print(f"  wrote {out} ({len(blob)} B)", file=sys.stderr)
    finally:
        d.stop()


if __name__ == "__main__":
    main()
