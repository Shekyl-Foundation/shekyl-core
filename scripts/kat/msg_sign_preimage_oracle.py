# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the message-signing preimage (NETWORK_IDENTITY.md NI-F2).

`docs/test_vectors/MSG_SIGN_PREIMAGE_V2.json` pins, for each case (a classical
segment and a message), the preimage a message signature is over on each
network (`WALLET_MESSAGE_SIGNING.md` SM-R-3, layout version 2):

    preimage = cSHAKE256-32(S = "shekyl/msg-sign-v1",
        X = sig_format_version || network_id || mode ||
            len(segment) as u16 LE || segment ||
            cSHAKE256-32(S = "shekyl/msg-hash-v1", X = message))

with `sig_format_version = 2`, `mode = 0x01` and `network_id` the network's
16-byte genesis-derived id. The cases' inputs are generated here from fixed
rules, so the file is reproducible from this script alone; the hash goes
through `stdlib_cshake.py`, which shares nothing with the Rust and is
anchored before use.

Modes: with no flag it checks that the pinned file is what it computes (exit
0, 1 on a mismatch, 2 when the file has no case, rule 47). With `--write` it
writes the file. Run with `python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/msg_sign_preimage_oracle.py [--write]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("stdlib_cshake", _HERE / "stdlib_cshake.py")
cs = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cs)

VECTORS = cs.ROOT / "docs/test_vectors/MSG_SIGN_PREIMAGE_V2.json"
MSG_SIGN_DST = b"shekyl/msg-sign-v1"
MSG_HASH_DST = b"shekyl/msg-hash-v1"
LAYOUT_VERSION = 2
MODE_SPEND = 0x01

# (name, segment, message). The 113-byte segment is a v1 address's length
# (version, spend key, view key, SLH key); the empty and the long ones hold
# the u16 length prefix to its framing at both ends.
CASES = (
    ("v1-length-segment", bytes(range(113)), b"shekyl message-signing KAT"),
    ("empty-message", bytes(range(113)), b""),
    ("empty-segment", b"", b"shekyl message-signing KAT"),
    ("long-segment-binary-message", bytes(i % 251 for i in range(300)), bytes(range(256)) * 2),
)


def preimage(nid: bytes, segment: bytes, message: bytes) -> bytes:
    msg_hash = cs.cshake256(message, 32, s=MSG_HASH_DST)
    x = (
        bytes([LAYOUT_VERSION])
        + nid
        + bytes([MODE_SPEND])
        + len(segment).to_bytes(2, "little")
        + segment
        + msg_hash
    )
    return cs.cshake256(x, 32, s=MSG_SIGN_DST)


def build() -> dict:
    ids = {name: cs.network_id(name) for name in cs.NETWORKS}
    return {
        "description": (
            "Message-signing preimages (WALLET_MESSAGE_SIGNING.md SM-R-3, layout "
            "version 2; NETWORK_IDENTITY.md NI-F2): the network field is the "
            "16-byte genesis-derived id. Generated and checked by "
            "scripts/kat/msg_sign_preimage_oracle.py; read by "
            "rust/shekyl-crypto-pq/tests/kat_msg_sign_preimage_v2.rs."
        ),
        "sig_format_version": LAYOUT_VERSION,
        "mode": MODE_SPEND,
        "network_ids": {name: ids[name].hex() for name in cs.NETWORKS},
        "cases": [
            {
                "name": name,
                "segment_hex": segment.hex(),
                "message_hex": message.hex(),
                "preimage_by_network": {
                    net: preimage(ids[net], segment, message).hex() for net in cs.NETWORKS
                },
            }
            for name, segment, message in CASES
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    cs.anchor()
    computed = build()
    if args.write:
        VECTORS.write_text(json.dumps(computed, indent=4, ensure_ascii=False) + "\n")
        print(f"wrote {len(computed['cases'])} cases to {VECTORS.relative_to(cs.ROOT)}")
        return 0
    pinned = json.loads(VECTORS.read_text())
    if not pinned.get("cases"):
        print("the vector file has no case", file=sys.stderr)
        return 2
    if pinned != computed:
        print(f"{VECTORS.relative_to(cs.ROOT)} is not the oracle's", file=sys.stderr)
        return 1
    print(
        f"message-signing preimage oracle: {len(computed['cases'])} cases x "
        f"{len(cs.NETWORKS)} networks match"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
