#!/usr/bin/env python3
"""Oracle-emit: capture a real FCMP++ spend transaction blob from a regtest shekyld.

Starts a throwaway regtest shekyld + shekyl-wallet-rpc, mines coinbase to a fresh
wallet, makes a self-transfer (a real FCMP++ spend), mines it, and writes the
daemon's canonical full tx blob to `regtest_spend.tx` (raw bytes). The C++ daemon
serializer is the genesis wire-format oracle; this blob feeds the spend round-trip
KAT in `../fcmp_spend_roundtrip.rs`.

Usage:  python3 capture_spend.py   [SHEKYLD_BIN / WALLET_RPC_BIN env override paths]
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
# checkout root (this file is rust/shekyl-wire/tests/vectors/ → 4 levels up).
# NOTE: in a git worktree the C++ build dir usually lives in the main checkout;
# set SHEKYLD_BIN / WALLET_RPC_BIN to point at it (e.g. <main>/build/bin/*).
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
SHEKYLD = os.environ.get("SHEKYLD_BIN", os.path.join(ROOT, "build", "bin", "shekyld"))
WALLET_RPC = os.environ.get("WALLET_RPC_BIN", os.path.join(ROOT, "build", "bin", "shekyl-wallet-rpc"))
MINE_BLOCKS = 200  # > maturity (60) AND deep enough that early coinbases are
#                    drained into the curve tree before the reference height (tip-6)


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
    with urllib.request.urlopen(req, timeout=120) as r:
        res = json.loads(r.read())
    if "error" in res:
        raise RuntimeError(f"{method} -> {res['error']}")
    return res["result"]


def wait_rpc(url, method, tries=120):
    for _ in range(tries):
        try:
            rpc(url, method)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"RPC at {url} not ready ({method})")


def main():
    dport, wport = free_port(), free_port()
    ddir = tempfile.mkdtemp(prefix="spendcap_d_")
    wdir = tempfile.mkdtemp(prefix="spendcap_w_")
    durl = f"http://127.0.0.1:{dport}/json_rpc"
    wurl = f"http://127.0.0.1:{wport}/json_rpc"
    dlog = open(os.path.join(ddir, "daemon.log"), "w")
    wlog = open(os.path.join(wdir, "wallet.log"), "w")

    daemon = subprocess.Popen(
        [SHEKYLD, "--regtest", "--offline", "--non-interactive", "--fixed-difficulty", "1",
         "--data-dir", ddir, "--rpc-bind-port", str(dport), "--log-level", "0"],
        stdout=dlog, stderr=subprocess.STDOUT)
    wallet = None
    try:
        print(f"daemon on {dport}, wallet-rpc on {wport}", file=sys.stderr)
        wait_rpc(durl, "get_info")

        # Daemon and wallet both run FAKECHAIN (--regtest): raw-seed creation is
        # allowed on fakechain, and fakechain addressing mirrors mainnet (the
        # `shekyl1` HRP the daemon's generateblocks parser expects). The wallet
        # --regtest flag is the harness enabler added on feat/regtest-wallet-harness.
        wallet = subprocess.Popen(
            [WALLET_RPC, "--regtest", "--daemon-address", f"127.0.0.1:{dport}", "--trusted-daemon",
             "--wallet-dir", wdir, "--rpc-bind-port", str(wport), "--disable-rpc-login",
             "--log-level", "0"],
            stdout=wlog, stderr=subprocess.STDOUT)
        wait_rpc(wurl, "get_version")

        rpc(wurl, "create_wallet", {"filename": "w", "password": "", "language": "English"})
        addr = rpc(wurl, "get_address", {"account_index": 0})["address"]
        print(f"wallet address: {addr[:16]}... (len {len(addr)})", file=sys.stderr)

        rpc(durl, "generateblocks", {"amount_of_blocks": MINE_BLOCKS, "wallet_address": addr})
        print(f"mined {MINE_BLOCKS} blocks", file=sys.stderr)

        unlocked = 0
        for _ in range(40):
            rpc(wurl, "refresh")
            bal = rpc(wurl, "get_balance", {"account_index": 0})
            unlocked = bal.get("unlocked_balance", 0)
            if unlocked > 0:
                break
            time.sleep(0.5)
        if unlocked == 0:
            raise RuntimeError("no unlocked balance after mining")
        print(f"unlocked balance: {unlocked}", file=sys.stderr)

        # --- diagnostic: probe the daemon's FCMP++ curve-tree-path RPC directly ---
        try:
            inc = rpc(wurl, "incoming_transfers", {"transfer_type": "available"})
            gidx = [t["global_index"] for t in (inc.get("transfers") or [])[:3]]
            print(f"sample available global indices: {gidx}", file=sys.stderr)
            dreq = urllib.request.Request(
                f"http://127.0.0.1:{dport}/get_curve_tree_path",
                data=json.dumps({"output_indices": gidx or [0]}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(dreq, timeout=60) as r:
                ctp = json.loads(r.read())
            print(f"get_curve_tree_path -> {json.dumps(ctp)[:500]}", file=sys.stderr)
        except Exception as e:
            print(f"diag get_curve_tree_path failed: {e}", file=sys.stderr)

        # Small amount: one matured coinbase output covers it, so the spend uses a
        # single FCMP++ input (cap is 8/tx) and stays well under MAX_TX_SIZE.
        amount = 1_000_000_000
        res = rpc(wurl, "transfer", {
            "destinations": [{"amount": amount, "address": addr}],
            "account_index": 0, "priority": 0, "get_tx_hex": True})
        tx_hash = res["tx_hash"]
        print(f"spend tx_hash: {tx_hash} (fee {res.get('fee')})", file=sys.stderr)

        # Mine the spend, then fetch the daemon's canonical full serialization.
        rpc(durl, "generateblocks", {"amount_of_blocks": 1, "wallet_address": addr})
        got = rpc(durl, "get_transactions", {"txs_hashes": [tx_hash], "decode_as_json": True, "prune": False})
        txs = got.get("txs") or []
        if not txs:
            raise RuntimeError("get_transactions returned nothing")
        as_hex = txs[0].get("as_hex") or txs[0].get("pruned_as_hex")
        blob = bytes.fromhex(as_hex)
        out = os.path.join(HERE, "regtest_spend.tx")
        with open(out, "wb") as f:
            f.write(blob)
        # sanity from decoded json
        j = json.loads(txs[0]["as_json"]) if "as_json" in txs[0] else {}
        print(f"wrote {out} ({len(blob)} B); vin={len(j.get('vin', []))} "
              f"vout={len(j.get('vout', []))} rct.type={j.get('rct_signatures', {}).get('type')}",
              file=sys.stderr)
    finally:
        for p in (wallet, daemon):
            if p and p.poll() is None:
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    p.kill()
        dlog.close()
        wlog.close()


if __name__ == "__main__":
    main()
