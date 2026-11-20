# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the bundle commitment (ARCHIVAL_SERVE_CREDIT_SPEC.md
§7.3; the signing envelope §2.4, §2.7).

The witness signs

    commitment = frame("shekyl/archival-serve-credit-bundle-v2", network_id,
                       [kept, records])[..64]
    kept       = seed[32] || h_le[8] || count_le[4] || bitmap
                 || support_count_le[4] || support_bitmap
    records    = r_1 || ... || r_n,  r_k = attempt[1] || anchor_le[8]
                 || delivery_digest[32] || receipt[1356]

64 bytes because a hybrid signature signs it, under the network's id because
the witness's seed is its own random value, so nothing else in the message is
network-bound.

The fixtures are the ones `shekyl-archival-retention`'s `bundle_tests.rs`
builds (record k: attempt k mod 3, anchor 999000 + k, digest (0xD0 + k) x 32,
receipt byte i = (7i + 13k + 1) mod 251; seed 0x11 x 32; h = 1000000), written
here from those formulas. Before computing anything the script reproduces the
`-v1` pins those tests carried, cSHAKE256-32 of `kept || records` under the
`-v1` label, so the preimages are the ones pinned independently before this
change. It prints the new pins on testnet, the network those tests use.

Exit 0 when the anchors hold, 1 otherwise. Run with `python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/bundle_commitment_oracle.py
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("stdlib_cshake", _HERE / "stdlib_cshake.py")
cs = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cs)

LABEL_V1 = b"shekyl/archival-serve-credit-bundle-v1"
LABEL = b"shekyl/archival-serve-credit-bundle-v2"
RECEIPT_LEN = 1356
SEED = b"\x11" * 32
H = 1_000_000


def record(k: int) -> bytes:
    receipt = bytes((i * 7 + k * 13 + 1) % 251 for i in range(RECEIPT_LEN))
    return bytes([k % 3]) + (999_000 + k).to_bytes(8, "little") + bytes([0xD0 + k]) * 32 + receipt


def records(n: int) -> bytes:
    return b"".join(record(k) for k in range(n))


def kept(h: int, count: int, bitmap: bytes, support_count: int = 0,
         support_bitmap: bytes = b"") -> bytes:
    return (SEED + h.to_bytes(8, "little") + count.to_bytes(4, "little") + bitmap
            + support_count.to_bytes(4, "little") + support_bitmap)


# (name, kept, records, the -v1 pin the Rust tests carried)
CASES = [
    ("no draws", kept(H, 0, b""), b"",
     "3d2a83a7b959e521e409e25e8aa03b528c475380ee8e0b4b8006c62ea74a9023"),
    ("eight draws, no pass", kept(H, 8, b"\x00"), b"",
     "2ce39ad03bb353db1f7115da22c4ce5564b021f48d2ba4322140851b0d31dc65"),
    ("one record", kept(H, 1, b"\x01"), record(0),
     "bcd6ae8354943380172c9ecc4e80decd4c2eb8a2006e0c1f3e17f8f103dd000c"),
    ("three records", kept(H, 12, b"\x01\x0a"), records(3),
     "7474d1f829369e895a6019f63a3c033ec5b438786cd17c69e91a52cda9d584d7"),
    ("three records at h + 1", kept(H + 1, 12, b"\x01\x0a"), records(3),
     "65ff3cc44efa77bc055ca3ff645d6d2881f880e6bd2ca60942e6e3af0609ec09"),
    ("one more economy bit", kept(H, 12, b"\x09\x0a"), records(3),
     "e6c849bf022b175965c02c9f402df9ba2d277d7a0cba457d5efe4b980e4230e0"),
    ("support draw 0", kept(H, 12, b"\x01\x0a", 1, b"\x01"), records(3),
     "f626f6c4af284f660f45679bd3c8126f9d3ddc914e80f3649ca9ad020f31a16d"),
]


def main() -> int:
    cs.anchor()
    for name, k, r, pinned in CASES:
        if cs.cshake256(k + r, 32, s=LABEL_V1).hex() != pinned:
            print(f"{name}: the preimage does not give the -v1 pin", file=sys.stderr)
            return 1
    testnet = cs.network_id("testnet")
    for name, k, r, _ in CASES:
        print(f"{name}: {cs.frame(LABEL, testnet, [k, r], 64).hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
