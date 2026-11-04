# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the spend signature's hash (NETWORK_IDENTITY.md NI-Q4).

`rust/shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json` carries, for
each pinned transaction, the per-input signing payloads the C++ assembly
produced before it was deleted. Since NI-Q4 the hash every hybrid spend
signature is over binds the network:

    signed_hash(i) = cSHAKE256-32(N = "", S = "shekyl/fcmp-spend-signing-v1",
                                  X = network_id || payload(i))

This script recomputes that hash for each payload on each network, through
code that shares nothing with the Rust: Keccak-f[1600] and the cSHAKE256
construction of NIST SP 800-185 written below, the network ids derived from
the network table's committed genesis hashes
(`rust/shekyl-network/genesis/<name>.hash`) with
`cSHAKE256(S = "shekyl/p2p-network-id-v1", X = genesis hash)[..16]`, and the
domain strings written out from the design, never parsed out of the Rust.

Its primitives are anchored before use: the sponge with an empty
customization against hashlib's SHAKE256, and the four derived network ids
against the values PR 1 recorded (`network_id_ffi.rs`).

Modes: with no flag it checks that every pinned `signed_hashes_by_network`
entry is what it computes (exit 0, or 1 on a mismatch, or 2 when the fixture
lacks a subject this oracle exists to check, rule 47). With `--write` it
writes those entries into the fixture. Run with `python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/spend_signing_hash_oracle.py [--write]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "rust/shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json"
GENESIS_DIR = ROOT / "rust/shekyl-network/genesis"

NETWORKS = ("mainnet", "testnet", "stagenet", "regtest")
NETWORK_ID_DST = b"shekyl/p2p-network-id-v1"
SPEND_SIGNING_DST = b"shekyl/fcmp-spend-signing-v1"

# The ids PR 1 recorded (rust/shekyl-ffi/src/network_id_ffi.rs), written out:
# the derivation below must reproduce them before it is trusted.
RECORDED_IDS = {
    "mainnet": "cf9f4283032b6ca19545f2696a228d80",
    "testnet": "8c207793b0f7a373dd418813477e7a72",
    "stagenet": "d839823161b34fbed969d6411e649d61",
    "regtest": "6545666f7b24eb45ef7c050de5932330",
}

# ---- Keccak-f[1600] -------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def _sponge(message: bytes, rate: int, domain: int, out_len: int) -> bytes:
    padded = bytearray(message)
    padded.append(domain)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            a[i % 5][i // 5] ^= lane
        _keccak_f(a)
    out = bytearray()
    while len(out) < out_len:
        for i in range(rate // 8):
            out += a[i % 5][i // 5].to_bytes(8, "little")
        if len(out) < out_len:
            _keccak_f(a)
    return bytes(out[:out_len])


# ---- cSHAKE256 (SP 800-185) ------------------------------------------------

_RATE = 136


def _left_encode(x: int) -> bytes:
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def _encode_string(s: bytes) -> bytes:
    return _left_encode(8 * len(s)) + s


def _bytepad(x: bytes, w: int) -> bytes:
    z = _left_encode(w) + x
    return z + b"\x00" * ((-len(z)) % w)


def cshake256(x: bytes, out_len: int, n: bytes = b"", s: bytes = b"") -> bytes:
    if not n and not s:
        return _sponge(x, _RATE, 0x1F, out_len)
    prefix = _bytepad(_encode_string(n) + _encode_string(s), _RATE)
    return _sponge(prefix + x, _RATE, 0x04, out_len)


# ---- the oracle -------------------------------------------------------------


def network_id(name: str) -> bytes:
    genesis = bytes.fromhex((GENESIS_DIR / f"{name}.hash").read_text().strip())
    return cshake256(genesis, 32, s=NETWORK_ID_DST)[:16]


def signed_hash(nid: bytes, payload: bytes) -> bytes:
    return cshake256(nid + payload, 32, s=SPEND_SIGNING_DST)


def anchor() -> None:
    for msg in (b"", b"abc", bytes(range(200))):
        if cshake256(msg, 32) != hashlib.shake_256(msg).digest(32):
            sys.exit("the Keccak sponge disagrees with hashlib's SHAKE256")
    for name in NETWORKS:
        if network_id(name).hex() != RECORDED_IDS[name]:
            sys.exit(f"{name}: the derived network id is not the one PR 1 recorded")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    anchor()
    ids = {name: network_id(name) for name in NETWORKS}
    doc = json.loads(FIXTURE.read_text())
    transactions = doc.get("transactions", [])
    with_payloads = [t for t in transactions if t.get("payloads_hex")]
    if not with_payloads:
        print("the fixture has no transaction with payloads", file=sys.stderr)
        return 2
    mismatches = 0
    for tx in transactions:
        payloads = [bytes.fromhex(p) for p in tx.get("payloads_hex", [])]
        computed = {
            name: [signed_hash(ids[name], p).hex() for p in payloads] for name in NETWORKS
        }
        if args.write:
            tx["signed_hashes_by_network"] = computed
        elif tx.get("signed_hashes_by_network") != computed:
            print(f"{tx.get('name')}: signed_hashes_by_network is not the oracle's", file=sys.stderr)
            mismatches += 1
    if args.write:
        FIXTURE.write_text(json.dumps(doc, indent=4, ensure_ascii=False) + "\n")
        print(f"wrote signed_hashes_by_network for {len(transactions)} transactions")
        return 0
    if mismatches:
        return 1
    print(
        f"spend signing hash oracle: {sum(len(t['payloads_hex']) for t in with_payloads)} "
        f"payloads x {len(NETWORKS)} networks match"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
