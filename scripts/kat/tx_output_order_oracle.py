# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for a transaction's output order (R-24).

`docs/test_vectors/TX_OUTPUT_ORDER_V1.json` pins, per transaction key, the
order `shekyl-crypto-pq`'s `TxKey::output_order` derives
(`output_order.rs`), as the design states it:

    stream  = block 0 ‖ block 1 ‖ …, block b = expand("shekyl/tx-output-order-v1" ‖ u64_le(b), 64)
              (HKDF-SHA-512, no salt, IKM the key's 32 scalar bytes),
              read as little-endian u32 words
    shuffle = recipient_at = [0, …, n-1]; for i = n-1 down to 1:
              j = uniform(i + 1); swap recipient_at[i], recipient_at[j]
    uniform(bound): draw words until w < 2^32 - (2^32 mod bound); j = w mod bound

and `position_of` its inverse, π(recipient). The keys are multisig intent
keys (`TxKey::from_intent_seed`): r = wide(expand("shekyl/multisig-intent-
tx-key-v1", 64)) off the intent seed, as `multisig_intent_derive_oracle.py`
states it, so a vector names a key any build can make. The labels are
written out below from the design text, never parsed out of the Rust
source. HKDF and Ed25519 are the hand-written RFC 5869 / RFC 8032 code of
`address_derivation_v3_oracle.py`, anchored there and run here before use.

Modes: with no flag it checks the pinned file (exit 0, 1 on a mismatch, 2
when the file is missing or pins no vector, rule 47). With `--write` it
writes the file. Run with `python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/tx_output_order_oracle.py [--write]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "address_derivation_v3_oracle", _HERE / "address_derivation_v3_oracle.py"
)
ad = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ad)

VECTORS = ad.ROOT / "docs/test_vectors/TX_OUTPUT_ORDER_V1.json"

LABEL_TX_KEY = b"shekyl/multisig-intent-tx-key-v1"
LABEL_TX_OUTPUT_ORDER = b"shekyl/tx-output-order-v1"
NO_SALT = b""
WIDE_LEN = 64
BLOCK_LEN = 64
WORD_LEN = 4
WORD_SPAN = 2**32
SEED_LEN = 32
# The wire's output cap (shekyl-wire MAX_OUTPUTS): the largest order a
# transaction takes.
MAX_OUTPUTS = 16

# The fixture: intent seeds that span the byte range, each with an output
# count; one, two and the cap among them.
CASES = [
    (bytes(SEED_LEN), 1),
    (bytes([0x51]) * SEED_LEN, 2),
    (bytes(range(SEED_LEN)), 3),
    (bytes([0x01]) * SEED_LEN, 3),
    (bytes([0xFF]) * SEED_LEN, 5),
    (bytes(range(SEED_LEN, 0, -1)), 7),
    (bytes([0xA5]) * SEED_LEN, MAX_OUTPUTS),
]


def tx_key(seed: bytes) -> int:
    return ad.scalar_from_wide(ad.hkdf512(NO_SALT, seed, LABEL_TX_KEY, WIDE_LEN))


def words(r: int):
    ikm = ad.scalar_bytes(r)
    block = 0
    while True:
        info = LABEL_TX_OUTPUT_ORDER + block.to_bytes(8, "little")
        data = ad.hkdf512(NO_SALT, ikm, info, BLOCK_LEN)
        for k in range(0, BLOCK_LEN, WORD_LEN):
            yield int.from_bytes(data[k : k + WORD_LEN], "little")
        block += 1


def uniform(stream, bound: int) -> int:
    zone = WORD_SPAN - WORD_SPAN % bound
    while True:
        w = next(stream)
        if w < zone:
            return w % bound


def order(r: int, n: int) -> list[int]:
    recipient_at = list(range(n))
    stream = words(r)
    for i in range(n - 1, 0, -1):
        j = uniform(stream, i + 1)
        recipient_at[i], recipient_at[j] = recipient_at[j], recipient_at[i]
    return recipient_at


def inverse(recipient_at: list[int]) -> list[int]:
    position_of = [0] * len(recipient_at)
    for position, recipient in enumerate(recipient_at):
        position_of[recipient] = position
    return position_of


def vectors() -> dict:
    out = []
    for seed, n in CASES:
        r = tx_key(seed)
        recipient_at = order(r, n)
        out.append(
            {
                "intent_seed_hex": seed.hex(),
                "tx_key_secret_hex": ad.scalar_bytes(r).hex(),
                "tx_key_public_hex": ad.scalar_base_mult(r).hex(),
                "outputs": n,
                "recipient_at": recipient_at,
                "position_of": inverse(recipient_at),
            }
        )
    # A vector whose order is its own inverse cannot tell π from π⁻¹: the
    # file must hold one that can (rule 47).
    if not any(v["recipient_at"] != v["position_of"] for v in out):
        raise SystemExit("FAIL: every vector's order is its own inverse; pick other cases")
    return {
        "description": (
            "A transaction's output order (R-24): per transaction key, recipient_at[p] is "
            "the recipient whose output sits at position p, and position_of its inverse. "
            "The keys are TxKey::from_intent_seed of the listed intent seeds. Written by "
            "scripts/kat/tx_output_order_oracle.py; checked by shekyl-crypto-pq "
            "tests/kat_tx_output_order.rs."
        ),
        "vectors": out,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="write the vectors file")
    args = parser.parse_args()
    ad.self_test()
    computed = vectors()
    if args.write:
        VECTORS.write_text(json.dumps(computed, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {VECTORS.relative_to(ad.ROOT)}: {len(computed['vectors'])} vectors")
        return 0
    if not VECTORS.exists():
        print(f"FAIL: {VECTORS.relative_to(ad.ROOT)} is missing", file=sys.stderr)
        return 2
    pinned = json.loads(VECTORS.read_text(encoding="utf-8"))
    if not pinned.get("vectors"):
        print("FAIL: the vectors file pins no vector", file=sys.stderr)
        return 2
    if pinned != computed:
        print(
            f"FAIL: {VECTORS.relative_to(ad.ROOT)} differs from the oracle's derivation",
            file=sys.stderr,
        )
        return 1
    print(f"transaction output order: {len(pinned['vectors'])} vectors match the oracle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
