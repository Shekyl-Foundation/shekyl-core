#!/usr/bin/env python3
"""CT-2 Tier-A reconstruct-root KAT fixture generator.

Drives a fresh regtest `shekyld` to mine the Tier-A chain shape
(`CT2_DRAIN_ORDER.md` §8.2) and records, per block, the consensus
`curve_tree_root` together with the coinbase leaf inputs (`O`, `C`,
`h_pqc`-bearing `tx_extra`) the wallet needs to reconstruct that root.

The recorded JSON is the hermetic oracle for the Rust KAT
(`tests/recon_kat.rs`): `build_layers` root == C++ header root.

This is dev tooling. It is *not* run in CI — its output
(`ct2_tier_a.json`) is checked in and the KAT replays it offline.
Regenerate only when the consensus leaf/root rules change (see README).

Why daemon JSON rather than a Rust block decode: Shekyl's coinbase
serializes a real `outPk` under `RCTTypeNull` (`rctTypes.h`
`serialize_rctsig_base`), which `shekyl-oxide`'s coinbase model
(`proofs: None`) does not parse. Until that gap closes (FOLLOWUPS),
the authoritative leaf inputs come from the daemon's structured block
JSON, which serializes `outPk`/vout/extra correctly.

Usage:
    python3 gen_ct2_fixture.py \
        --daemon ../../../../build/bin/shekyld \
        --out ct2_tier_a.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# Consensus windows (mirror shekyl-curve-tree::recon constants).
COINBASE_LOCK = 60
SPENDABLE_AGE = 10

# Tier-A chain shape. The founder coinbase matures at +60 but a matured leaf
# enters the tree on connection of the next block (drained_through = H - 1), so
# the first non-empty tree is at height 61. MAIN runs far enough past that to
# freeze a level-0 subtree and reach into level-1 (one coinbase leaf per block
# => MAIN-60 leaves at the tip).
MAIN_TIP = 210
DEEP_POP = 70   # >= COINBASE_LOCK+1: trims already-drained leaves (§6 trim branch)
DEEP_REGEN = 72
SHALLOW_POP = 5  # < COINBASE_LOCK+1: pops only pending coinbases (§6 no-mutation branch)
SHALLOW_REGEN = 7

# Genesis treasury address (regtest accepts the mainnet genesis address
# for generateblocks; coinbase outputs land in the curve tree identically).
GENESIS_RECIPIENTS = (
    Path(__file__).resolve().parents[5]
    / "shekyl-dev/tools/genesis_builder/genesis_recipients.mainnet.json"
)


def load_miner_address() -> str:
    data = json.loads(GENESIS_RECIPIENTS.read_text())
    return data["recipients"][0]["address"]


class Daemon:
    """A throwaway regtest daemon with a temp data-dir."""

    def __init__(self, binary: str, port: int):
        self.binary = binary
        self.port = port
        self.url = f"http://127.0.0.1:{port}/json_rpc"
        self.base = f"http://127.0.0.1:{port}"
        self.workdir = tempfile.mkdtemp(prefix="ct2_fixture_")
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        log = open(os.path.join(self.workdir, "daemon.log"), "w")
        self.proc = subprocess.Popen(
            [
                self.binary,
                "--regtest",
                "--offline",
                "--non-interactive",
                "--fixed-difficulty",
                "1",
                "--data-dir",
                self.workdir,
                "--rpc-bind-port",
                str(self.port),
                "--log-level",
                "0",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        # Wait for RPC readiness.
        for _ in range(60):
            try:
                if self.json_rpc("get_info").get("status") == "OK":
                    return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("daemon RPC did not become ready")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def json_rpc(self, method: str, params: dict | None = None) -> dict:
        body = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params is not None:
            body["params"] = params
        req = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        resp = json.load(urllib.request.urlopen(req, timeout=120))
        if "error" in resp and resp["error"]:
            raise RuntimeError(f"{method} failed: {resp['error']}")
        return resp["result"]

    def other_rpc(self, path: str, params: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base}/{path}",
            data=json.dumps(params).encode(),
            headers={"Content-Type": "application/json"},
        )
        return json.load(urllib.request.urlopen(req, timeout=120))

    def height(self) -> int:
        return self.json_rpc("get_info")["height"]

    def generate(self, n: int, address: str) -> None:
        self.json_rpc(
            "generateblocks", {"amount_of_blocks": n, "wallet_address": address}
        )

    def pop(self, n: int) -> None:
        self.other_rpc("pop_blocks", {"nblocks": n})


def output_target(target: dict) -> tuple[str, str]:
    """Return (kind, output_key_hex) for a vout target."""
    if "tagged_key" in target:
        return "tagged_key", target["tagged_key"]["key"]
    if "key" in target:
        return "key", target["key"]
    raise RuntimeError(f"unexpected vout target: {target}")


# tx_extra tags (mirror shekyl-scanner::extra). 0x06/0x07 (and 0x02/0x04/0xDE)
# carry a varint length prefix; 0x01 is a bare 32-byte point; 0x00 is padding.
TAG_PQC_LEAF_HASHES = 0x07


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise RuntimeError(f"truncated tx_extra varint at offset {pos}")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        # A 64-bit value needs at most 10 continuation bytes; anything longer
        # is a malformed/oversized varint. Fail loudly per the "raise rather
        # than guess" discipline instead of shifting unboundedly.
        if shift > 63:
            raise RuntimeError(f"oversized tx_extra varint ending at offset {pos}")
    return val, pos


def extract_leaf_hash_blob(extra: bytes) -> bytes:
    """Walk tx_extra and return the single 0x07 leaf-hash blob.

    Mirrors the field framing in `shekyl-scanner::extra::ExtraField::read`
    so the generator records exactly the bytes `recon::extract_leaf_hashes`
    consumes. Raises on an unknown tag rather than guessing.
    """
    pos = 0
    n = len(extra)
    while pos < n:
        tag = extra[pos]
        pos += 1
        if tag == 0x00:  # padding: zeros to end
            while pos < n and extra[pos] == 0:
                pos += 1
        elif tag == 0x01:  # tx public key: 32 bytes
            pos += 32
        elif tag == 0x03:  # merge mining: varint + 32-byte hash
            _, pos = _read_varint(extra, pos)
            pos += 32
        elif tag == 0x04:  # additional pubkeys: varint count + count*32
            count, pos = _read_varint(extra, pos)
            pos += count * 32
        elif tag in (0x02, 0x06, 0x07, 0xDE):  # varint length + payload
            length, pos = _read_varint(extra, pos)
            payload = extra[pos : pos + length]
            pos += length
            if tag == TAG_PQC_LEAF_HASHES:
                return payload
        else:
            raise RuntimeError(f"unknown tx_extra tag 0x{tag:02x} at offset {pos - 1}")
    return b""


def record_block(daemon: Daemon, height: int) -> dict:
    blk = daemon.json_rpc("get_block", {"height": height})
    root = blk["block_header"]["curve_tree_root"]
    miner = json.loads(blk["json"])["miner_tx"]
    rct = miner.get("rct_signatures", {})
    out_pk = rct.get("outPk", [])
    outputs = []
    for i, vout in enumerate(miner["vout"]):
        kind, okey = output_target(vout["target"])
        commitment = out_pk[i] if i < len(out_pk) else None
        outputs.append(
            {"output_key": okey, "commitment": commitment, "target": kind}
        )
    extra = bytes(miner.get("extra", []))
    leaf_blob = extract_leaf_hash_blob(extra)
    # Guard: a well-formed Tier-A coinbase carries one 32-byte h_pqc per
    # output. A mis-parsed walk would not line up here.
    expected = len(outputs) * 32
    if len(leaf_blob) != expected:
        raise RuntimeError(
            f"height {height}: 0x07 blob is {len(leaf_blob)} B, expected {expected}"
        )
    return {
        "height": height,
        "curve_tree_root": root,
        # The 0x07 leaf-hash blob: recon::extract_leaf_hashes's input. The
        # scanner Extra tag-parse seam (adversarial framing) is the Tier-B
        # obligation (CT2_DRAIN_ORDER.md §3.1); Tier-A is well-formed.
        "miner_tx": {"pqc_leaf_hashes": leaf_blob.hex(), "outputs": outputs},
    }


def record_chain(daemon: Daemon, name: str) -> dict:
    tip = daemon.height() - 1
    blocks = [record_block(daemon, h) for h in range(tip + 1)]
    print(f"  recorded chain '{name}': heights 0..{tip} ({len(blocks)} blocks)")
    return {"name": name, "tip": tip, "blocks": blocks}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", required=True, help="path to shekyld binary")
    ap.add_argument("--port", type=int, default=28099)
    ap.add_argument("--out", required=True, help="fixture JSON output path")
    args = ap.parse_args()

    address = load_miner_address()
    daemon = Daemon(os.path.abspath(args.daemon), args.port)
    chains = []
    try:
        print(f"starting regtest daemon (workdir={daemon.workdir})")
        daemon.start()

        # MAIN: empty window 0..=60, first founder drain at 61, segment freeze.
        print(f"mining MAIN to height {MAIN_TIP}")
        daemon.generate(MAIN_TIP - (daemon.height() - 1), address)
        chains.append(record_chain(daemon, "main"))

        # DEEP reorg: trims already-drained leaves (§6 trim branch).
        print(f"deep reorg: pop {DEEP_POP}, regen {DEEP_REGEN}")
        daemon.pop(DEEP_POP)
        daemon.generate(DEEP_REGEN, address)
        chains.append(record_chain(daemon, "reorg_deep"))

        # SHALLOW reorg: pops only pending coinbases (§6 no-mutation branch).
        print(f"shallow reorg: pop {SHALLOW_POP}, regen {SHALLOW_REGEN}")
        daemon.pop(SHALLOW_POP)
        daemon.generate(SHALLOW_REGEN, address)
        chains.append(record_chain(daemon, "reorg_shallow"))
    finally:
        daemon.stop()

    fixture = {
        "_comment": (
            "CT-2 Tier-A reconstruct-root KAT oracle. Generated by "
            "gen_ct2_fixture.py from a regtest shekyld. Each chain's "
            "block[h].curve_tree_root is the C++ consensus header root; "
            "the Rust KAT reconstructs it from the coinbase leaf inputs."
        ),
        "network": "regtest",
        "coinbase_lock": COINBASE_LOCK,
        "spendable_age": SPENDABLE_AGE,
        "main_tip": MAIN_TIP,
        "deep_pop": DEEP_POP,
        "shallow_pop": SHALLOW_POP,
        "chains": chains,
    }
    out = Path(args.out)
    out.write_text(json.dumps(fixture, indent=1) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes, {len(chains)} chains)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
