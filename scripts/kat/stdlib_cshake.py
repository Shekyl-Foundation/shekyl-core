# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Stdlib Keccak-f[1600], cSHAKE256 and the network ids, for the KAT oracles.

Shared by the oracles in this directory that check a network-bound hash
(`spend_signing_hash_oracle.py`, `msg_sign_preimage_oracle.py`). It shares
nothing with the Rust: Keccak-f[1600] and the cSHAKE256 construction of NIST
SP 800-185 are written below, the network ids are derived from the network
table's committed genesis hashes (`rust/shekyl-network/genesis/<name>.hash`)
with `cSHAKE256(S = "shekyl/p2p-network-id-v1", X = genesis hash)[..16]`, and
the domain strings are written out from the design, never parsed out of the
Rust.

`anchor()` checks the primitives before an oracle trusts them: the sponge with
an empty customization against hashlib's SHAKE256, and the four derived
network ids against the values PR 1 recorded (`network_id_ffi.rs`).

An oracle loads this file by its path (`importlib`), as `python3 -I` puts
neither the script's directory nor the working directory on `sys.path`.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
GENESIS_DIR = ROOT / "rust/shekyl-network/genesis"

NETWORKS = ("mainnet", "testnet", "stagenet", "regtest")
NETWORK_ID_DST = b"shekyl/p2p-network-id-v1"

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


# ---- the network ids ----------------------------------------------------------


def network_id(name: str) -> bytes:
    genesis = bytes.fromhex((GENESIS_DIR / f"{name}.hash").read_text().strip())
    return cshake256(genesis, 32, s=NETWORK_ID_DST)[:16]


def anchor() -> None:
    for msg in (b"", b"abc", bytes(range(200))):
        if cshake256(msg, 32) != hashlib.shake_256(msg).digest(32):
            sys.exit("the Keccak sponge disagrees with hashlib's SHAKE256")
    for name in NETWORKS:
        if network_id(name).hex() != RECORDED_IDS[name]:
            sys.exit(f"{name}: the derived network id is not the one PR 1 recorded")
