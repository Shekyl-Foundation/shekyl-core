# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the multisig intent derivations (R-14, PQC_MULTISIG.md §9.5).

`docs/test_vectors/MULTISIG_INTENT_DERIVE_V1.json` pins, per seed, every
value a member derives from an intent's `kem_randomness_seed`
(`shekyl-crypto-pq` `multisig_intent.rs`), each as the design states it:
HKDF-SHA-512 with no salt and the seed as IKM, and

    tx key r          = wide(expand("shekyl/multisig-intent-tx-key-v1", 64)), R = r·G
    blind j (j < n-1) = wide(expand("shekyl/multisig-intent-pseudo-out-blind-v1" ‖ u64_le(j), 64))
    blind n-1         = Σ output masks − Σ blinds 0..n-2   (mod ℓ)
    rerandomize j     = expand("shekyl/multisig-intent-rerandomize-v1" ‖ u64_le(j), 32)
    fingerprint       = expand("shekyl/multisig-intent-seed-fingerprint-v1", 32)

with `wide` the little-endian 64-byte integer reduced mod ℓ and `j` the
input's position in the intent. The labels are written out below from the
design text, never parsed out of the Rust source. HKDF and Ed25519 are the
hand-written RFC 5869 / RFC 8032 code of `address_derivation_v3_oracle.py`,
anchored there (RFC 5869 test case 1, RFC 8032 test 1) and run here before
use; RFC 5869's absent salt is HashLen zero bytes, which HMAC pads alike to
the empty key used here.

Modes: with no flag it checks the pinned file (exit 0, 1 on a mismatch, 2
when the file is missing or pins no vector, rule 47). With `--write` it
writes the file. Run with `python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/multisig_intent_derive_oracle.py [--write]
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

VECTORS = ad.ROOT / "docs/test_vectors/MULTISIG_INTENT_DERIVE_V1.json"

LABEL_TX_KEY = b"shekyl/multisig-intent-tx-key-v1"
LABEL_PSEUDO_OUT_BLIND = b"shekyl/multisig-intent-pseudo-out-blind-v1"
LABEL_RERANDOMIZE = b"shekyl/multisig-intent-rerandomize-v1"
LABEL_SEED_FINGERPRINT = b"shekyl/multisig-intent-seed-fingerprint-v1"
NO_SALT = b""
WIDE_LEN = 64
SEED_LEN = 32
OUT_LEN = 32

# The fixture: seeds that span the byte range, an input count per seed,
# and the outputs' masks the last blind balances.
CASES = [
    (bytes(SEED_LEN), 1, [7]),
    (bytes([0x51]) * SEED_LEN, 2, [7, 11]),
    (bytes(range(SEED_LEN)), 3, [5, 9, 13]),
    (bytes([0xFF]) * SEED_LEN, 4, [ad.L - 1, 2**200 + 3]),
]


def expand(seed: bytes, info: bytes, length: int) -> bytes:
    return ad.hkdf512(NO_SALT, seed, info, length)


def indexed(label: bytes, j: int) -> bytes:
    return label + j.to_bytes(8, "little")


def derive(seed: bytes, inputs: int, masks: list[int]) -> dict:
    r = ad.scalar_from_wide(expand(seed, LABEL_TX_KEY, WIDE_LEN))
    blinds = [
        ad.scalar_from_wide(expand(seed, indexed(LABEL_PSEUDO_OUT_BLIND, j), WIDE_LEN))
        for j in range(inputs - 1)
    ]
    blinds.append((sum(masks) - sum(blinds)) % ad.L)
    return {
        "tx_key_secret_hex": ad.scalar_bytes(r).hex(),
        "tx_key_public_hex": ad.scalar_base_mult(r).hex(),
        "pseudo_out_blinds_hex": [ad.scalar_bytes(b).hex() for b in blinds],
        "rerandomization_seeds_hex": [
            expand(seed, indexed(LABEL_RERANDOMIZE, j), OUT_LEN).hex() for j in range(inputs)
        ],
        "seed_fingerprint_hex": expand(seed, LABEL_SEED_FINGERPRINT, OUT_LEN).hex(),
    }


def vectors() -> dict:
    return {
        "description": (
            "Multisig intent derivations (R-14, PQC_MULTISIG.md §9.5): from an intent's "
            "kem_randomness_seed, the transaction key, each input's pseudo-out blind (the "
            "last balancing the output masks) and rerandomization seed, and the seed's "
            "replay fingerprint. Written by scripts/kat/multisig_intent_derive_oracle.py; "
            "checked by shekyl-crypto-pq tests/kat_multisig_intent_derive.rs (the derived "
            "values) and shekyl-ct-balance tests/kat_pseudo_out_blinds.rs (the balanced "
            "blinds)."
        ),
        "vectors": [
            {
                "seed_hex": seed.hex(),
                "inputs": inputs,
                "output_masks_hex": [ad.scalar_bytes(m % ad.L).hex() for m in masks],
                "expected": derive(seed, inputs, masks),
            }
            for seed, inputs, masks in CASES
        ],
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
    print(f"multisig intent derivations: {len(pinned['vectors'])} vectors match the oracle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
