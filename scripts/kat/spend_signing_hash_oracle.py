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

This script recomputes that hash for each payload on each network through
`stdlib_cshake.py`, which shares nothing with the Rust and is anchored before
use.

Modes: with no flag it checks that every pinned `signed_hashes_by_network`
entry is what it computes (exit 0, or 1 on a mismatch, or 2 when the fixture
lacks a subject this oracle exists to check, rule 47). With `--write` it
writes those entries into the fixture. Run with `python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/spend_signing_hash_oracle.py [--write]
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

FIXTURE = cs.ROOT / "rust/shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json"
SPEND_SIGNING_DST = b"shekyl/fcmp-spend-signing-v1"


def signed_hash(nid: bytes, payload: bytes) -> bytes:
    return cs.cshake256(nid + payload, 32, s=SPEND_SIGNING_DST)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    cs.anchor()
    ids = {name: cs.network_id(name) for name in cs.NETWORKS}
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
            name: [signed_hash(ids[name], p).hex() for p in payloads] for name in cs.NETWORKS
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
        f"payloads x {len(cs.NETWORKS)} networks match"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
