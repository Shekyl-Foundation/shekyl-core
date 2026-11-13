# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the multisig spend intent, version 2 (R-5, R-13).

`docs/test_vectors/MULTISIG_INTENT_V2.json` pins, for fixed intents, the
canonical bytes and `intent_hash = Keccak-256(canonical bytes)`
(`rust/shekyl-multisig/src/intent.rs`, `SpendIntent::to_canonical_bytes`):

    version(1) || intent_id(32) || address_fingerprint(32) || proposer_index(1) ||
    u32(len) || signers || responder_index(1) || created_at(8) || tx_counter(8) ||
    reference_block_height(8) || reference_block_hash(32) ||
    u32(count) || { u32(len) || address || amount(8) }* || fee(8) ||
    u32(count) || input_global_index(8)* || kem_randomness_seed(32) ||
    chain_state_fingerprint(32)

integers little-endian. The layout is written here from the spec, not from
the Rust; Keccak-256 is `stdlib_cshake.py`'s, anchored on its published
values before use.

Modes: with no flag it checks the pinned file (exit 0, 1 on a mismatch, 2
when it pins no vector, rule 47). With `--write` it writes the file. Run with
`python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/multisig_intent_oracle.py [--write]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import struct
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("stdlib_cshake", _HERE / "stdlib_cshake.py")
cs = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cs)

VECTORS = cs.ROOT / "docs/test_vectors/MULTISIG_INTENT_V2.json"
SPEND_INTENT_VERSION = 2


def u32(n: int) -> bytes:
    return struct.pack("<I", n)


def u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def canonical(i: dict) -> bytes:
    out = bytes([i["version"]])
    out += bytes.fromhex(i["intent_id"])
    out += bytes.fromhex(i["address_fingerprint"])
    out += bytes([i["proposer_index"]])
    out += u32(len(i["signers"])) + bytes(i["signers"])
    out += bytes([i["responder_index"]])
    out += u64(i["created_at"]) + u64(i["tx_counter"]) + u64(i["reference_block_height"])
    out += bytes.fromhex(i["reference_block_hash"])
    out += u32(len(i["recipients"]))
    for r in i["recipients"]:
        address = bytes.fromhex(r["address"])
        out += u32(len(address)) + address + u64(r["amount"])
    out += u64(i["fee"])
    out += u32(len(i["input_global_indices"]))
    for g in i["input_global_indices"]:
        out += u64(g)
    out += bytes.fromhex(i["kem_randomness_seed"])
    out += bytes.fromhex(i["chain_state_fingerprint"])
    return out


def fixtures() -> list[dict]:
    two_of_three = {
        "name": "2-of-3, member 0 proposes, member 2 responds",
        "version": SPEND_INTENT_VERSION,
        "intent_id": "42" * 32,
        "address_fingerprint": "bb" * 32,
        "proposer_index": 0,
        "signers": [0, 2],
        "responder_index": 2,
        "created_at": 1_000_000,
        "tx_counter": 1,
        "reference_block_height": 999_900,
        "reference_block_hash": "cc" * 32,
        "recipients": [{"address": "01020304", "amount": 1_000_000_000}],
        "fee": 1_000_000,
        "input_global_indices": [12345],
        "kem_randomness_seed": "dd" * 32,
        "chain_state_fingerprint": "ee" * 32,
    }
    three_of_five = {
        "name": "3-of-5, member 3 proposes, member 1 responds, two recipients, three inputs",
        "version": SPEND_INTENT_VERSION,
        "intent_id": "".join(f"{b:02x}" for b in range(32)),
        "address_fingerprint": "5a" * 32,
        "proposer_index": 3,
        "signers": [1, 3, 4],
        "responder_index": 1,
        "created_at": 1_800_000_000,
        "tx_counter": 7,
        "reference_block_height": 2_000_000,
        "reference_block_hash": "".join(f"{255 - b:02x}" for b in range(32)),
        "recipients": [
            {"address": "aa" * 70, "amount": 25_000_000_000},
            {"address": "bb" * 3, "amount": 3},
        ],
        "fee": 412_000,
        "input_global_indices": [9, 1 << 40, (1 << 64) - 1],
        "kem_randomness_seed": "13" * 32,
        "chain_state_fingerprint": "37" * 32,
    }
    return [two_of_three, three_of_five]


def build() -> dict:
    vectors = []
    for fixture in fixtures():
        bytes_ = canonical(fixture)
        vectors.append(
            {
                **fixture,
                "canonical": bytes_.hex(),
                "intent_hash": cs.keccak256(bytes_).hex(),
            }
        )
    return {
        "description": (
            "Multisig spend intent version 2 (R-5, R-13): canonical bytes and "
            "intent_hash = Keccak-256(canonical bytes) for fixed intents. Written and "
            "checked by scripts/kat/multisig_intent_oracle.py; read by shekyl-multisig's "
            "intent_v2_vectors test."
        ),
        "vectors": vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    cs.anchor()
    computed = build()
    if args.write:
        VECTORS.write_text(json.dumps(computed, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {len(computed['vectors'])} intents to {VECTORS.relative_to(cs.ROOT)}")
        return 0
    pinned = json.loads(VECTORS.read_text())
    if not pinned.get("vectors"):
        print("the vector file pins no intent", file=sys.stderr)
        return 2
    if pinned != computed:
        print(f"{VECTORS.relative_to(cs.ROOT)} is not the oracle's", file=sys.stderr)
        return 1
    print(f"multisig intent oracle: {len(computed['vectors'])} intents match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
