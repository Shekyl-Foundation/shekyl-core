# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Stdlib Keccak-f[1600], cSHAKE256 and the network ids, for the KAT oracles.

Shared by the oracles in this directory that check a network-bound hash
(`address_derivation_v3_oracle.py`, and the signing oracles). It shares
nothing with the Rust: Keccak-f[1600] and the cSHAKE256 construction of NIST
SP 800-185 are written below, the network ids are derived from the network
table's committed genesis hashes (`rust/shekyl-network/genesis/<name>.hash`)
with `cSHAKE256(S = "shekyl/p2p-network-id-v1", X = genesis hash)[..16]`, and
the domain strings are written out from the design, never parsed out of the
Rust.

`anchor_sponge()` checks the construction before an oracle trusts it: the
sponge with an empty customization against hashlib's SHAKE256, and cSHAKE256
with a customization against NIST SP 800-185's published samples #3 and #4
(`cSHAKE_samples.pdf`, written out below), which exercise the bytepad and
encode_string prefix and the 0x04 suffix that SHAKE256 does not (Rick's
ruling 3 on the signing envelope, 2026-11-04). `anchor()` adds the four
derived network ids against the recorded values (`shekyl-network`'s `RECORDED`),
and `name_id` is pinned for all four networks (the envelope §2.6).
`framed()` and `frame()` are the envelope's §2.6, written from the design.

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

# The ids rust/shekyl-network/src/tests.rs records (`RECORDED`), written out:
# the derivation below must reproduce them before it is trusted.
RECORDED_IDS = {
    "mainnet": "7e3f3a942e40b64e1dd7282d0f7dbe84",
    "testnet": "c2b6ad87de2c554007bc546e8465efbd",
    "stagenet": "fb751c941b828e4affe36b723f066d6c",
    "regtest": "757196fba508401a7a1361631da11c96",
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


# ---- the anchors and the two 16-byte bindings ----------------------------------

# NIST SP 800-185 cSHAKE256 samples #3 and #4 (N = "", S = "Email Signature",
# 512-bit output), from NIST's published cSHAKE_samples.pdf.
NIST_CSHAKE256_SAMPLES = (
    (
        bytes(range(4)),
        "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1"
        "64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
    ),
    (
        bytes(range(200)),
        "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917"
        "27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb",
    ),
)

NETWORK_NAME_DST = b"shekyl/network-name-v1"

# name_id for each network: the envelope §2.6, pinned here as Rick's ruling
# asks ("a test pins all four"); name_id() must reproduce them.
PINNED_NAME_IDS = {
    "mainnet": "5e6f51beafca4a33dbc98267574fc1c8",
    "testnet": "866a986774ba359c8950f938e8deb30a",
    "stagenet": "fd3a11446a2937826860949474456312",
    "regtest": "4b22be743ef0c275c6f9b05bb44ff33f",
}


def name_id(name: str) -> bytes:
    """cSHAKE256(X = the network's tag, S = shekyl/network-name-v1)[..16]."""
    return cshake256(f"shekyl/{name}".encode("ascii"), 32, s=NETWORK_NAME_DST)[:16]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 with the original 0x01 padding (not SHA3-256): the txid's
    and the prefix hash's function."""
    return _sponge(data, _RATE, 0x01, 32)


# Keccak-256 of the empty string and of "abc", the published values.
KECCAK256_SAMPLES = (
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
)


def anchor_sponge() -> None:
    for msg in (b"", b"abc", bytes(range(200))):
        if cshake256(msg, 32) != hashlib.shake_256(msg).digest(32):
            sys.exit("the Keccak sponge disagrees with hashlib's SHAKE256")
    for msg, want in KECCAK256_SAMPLES:
        if keccak256(msg).hex() != want:
            sys.exit("Keccak-256 disagrees with its published value")
    for data, want in NIST_CSHAKE256_SAMPLES:
        if cshake256(data, 64, s=b"Email Signature").hex() != want:
            sys.exit("cSHAKE256 disagrees with NIST SP 800-185's published sample")
    for name, want in PINNED_NAME_IDS.items():
        if name_id(name).hex() != want:
            sys.exit(f"{name}: name_id is not the pinned value")



def framed(field: bytes) -> bytes:
    """The envelope's field framing (§2.6): u64_le(len) ‖ field."""
    return len(field).to_bytes(8, "little") + field


def frame(domain: bytes, binding: bytes, fields: list[bytes], out_len: int = 32) -> bytes:
    """The signing envelope (§2.6): cSHAKE256(S = domain,
    X = binding ‖ framed(f_1) ‖ … ‖ framed(f_n)), out_len bytes. The binding is
    16 bytes, raw: a network id or a name_id."""
    if len(binding) != 16:
        sys.exit(f"a binding is 16 bytes, not {len(binding)}")
    return cshake256(binding + b"".join(framed(f) for f in fields), out_len, s=domain)


def network_id(name: str) -> bytes:
    genesis = bytes.fromhex((GENESIS_DIR / f"{name}.hash").read_text().strip())
    return cshake256(genesis, 32, s=NETWORK_ID_DST)[:16]


def anchor() -> None:
    anchor_sponge()
    for name in NETWORKS:
        if network_id(name).hex() != RECORDED_IDS[name]:
            sys.exit(f"{name}: the derived network id is not the recorded one")
