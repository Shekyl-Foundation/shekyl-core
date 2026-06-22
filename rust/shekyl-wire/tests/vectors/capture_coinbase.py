#!/usr/bin/env python3
"""Oracle-emit: capture coinbase block blobs + their consensus hashes.

Mines a few coinbase blocks on a throwaway regtest shekyld (to the genesis
treasury address — no wallet needed) and, for heights 0/1/2, writes the raw
block blob (`regtest_coinbase_h{h}.block`) plus the daemon's reported
`block_header.hash` and `miner_tx_hash` (`regtest_coinbase_hashes.json`). The C++
daemon is the genesis hashing oracle (GENESIS_TX_WIRE_FORMAT.md §11); these feed
the round-trip KAT (`../block.rs` analogue) and the hash KAT
(`../coinbase_hash.rs`).

Usage: python3 capture_coinbase.py   [SHEKYLD_BIN / GENESIS_RECIPIENTS env override]
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# checkout root (this file is rust/shekyl-wire/tests/vectors/ → 4 levels up). In a
# git worktree the C++ build is usually in the main checkout; set SHEKYLD_BIN.
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
SHEKYLD = os.environ.get("SHEKYLD_BIN", os.path.join(ROOT, "build", "bin", "shekyld"))
GENESIS_RECIPIENTS = os.environ.get(
    "GENESIS_RECIPIENTS",
    os.path.abspath(os.path.join(ROOT, "..", "shekyl-dev", "tools", "genesis_builder",
                                 "genesis_recipients.mainnet.json")))
N_BLOCKS = 5
CAPTURE_HEIGHTS = [0, 1, 2]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def rpc(url, method, params=None):
    body = {"jsonrpc": "2.0", "id": "0", "method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        res = json.loads(r.read())
    if "error" in res:
        raise RuntimeError(f"{method} -> {res['error']}")
    return res["result"]


def start_daemon(workdir, attempts=5):
    """Launch shekyld, retrying on a fresh port if it dies before its RPC is ready.

    `free_port()` has an inherent TOCTOU race — the port can be claimed between the
    probe and shekyld's bind — which surfaces as the daemon exiting early. Detect that
    (and a plain readiness timeout) and retry on a new port instead of failing the whole
    capture. Returns (daemon, url, log); raises if every attempt fails.
    """
    last = "unknown"
    for attempt in range(attempts):
        port = free_port()
        url = f"http://127.0.0.1:{port}/json_rpc"
        log = open(os.path.join(workdir, f"daemon.{attempt}.log"), "w")
        daemon = subprocess.Popen(
            [SHEKYLD, "--regtest", "--offline", "--non-interactive", "--fixed-difficulty", "1",
             "--data-dir", workdir, "--rpc-bind-port", str(port), "--log-level", "0"],
            stdout=log, stderr=subprocess.STDOUT)
        for _ in range(120):
            if daemon.poll() is not None:
                last = (f"daemon exited early (rc={daemon.returncode}) on port {port} "
                        "— likely a port conflict")
                break
            try:
                if rpc(url, "get_info").get("status") == "OK":
                    return daemon, url, log
            except Exception:
                pass
            time.sleep(0.5)
        else:
            last = f"daemon RPC not ready after ~60s on port {port} (see {log.name})"
        if daemon.poll() is None:
            daemon.send_signal(signal.SIGINT)
            try:
                daemon.wait(timeout=20)
            except subprocess.TimeoutExpired:
                daemon.kill()
        log.close()
    raise RuntimeError(f"shekyld failed to start after {attempts} attempts: {last}")


def main():
    with open(GENESIS_RECIPIENTS) as f:
        addr = json.load(f)["recipients"][0]["address"]
    workdir = tempfile.mkdtemp(prefix="cbcap_")
    daemon, url, log = start_daemon(workdir)
    try:
        rpc(url, "generateblocks", {"amount_of_blocks": N_BLOCKS, "wallet_address": addr})
        hashes = {}
        for h in CAPTURE_HEIGHTS:
            blk = rpc(url, "get_block", {"height": h})
            blob = bytes.fromhex(blk["blob"])
            out = os.path.join(HERE, f"regtest_coinbase_h{h}.block")
            with open(out, "wb") as f:
                f.write(blob)
            hashes[str(h)] = {
                "block_hash": blk["block_header"]["hash"],
                "miner_tx_hash": blk["miner_tx_hash"],
            }
            print(f"  h{h}: {len(blob)}B block_hash={hashes[str(h)]['block_hash'][:16]}...",
                  file=sys.stderr)
        with open(os.path.join(HERE, "regtest_coinbase_hashes.json"), "w") as f:
            json.dump(hashes, f, indent=2, sort_keys=True)
        print("wrote regtest_coinbase_hashes.json", file=sys.stderr)
    finally:
        if daemon.poll() is None:
            daemon.send_signal(signal.SIGINT)
            try:
                daemon.wait(timeout=20)
            except subprocess.TimeoutExpired:
                daemon.kill()
        log.close()
        # Clean up the throwaway regtest dir unless asked to keep it for debugging.
        if os.environ.get("KEEP_WORKDIR"):
            print(f"kept workdir: {workdir}", file=sys.stderr)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
