# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the emission auth digests (NETWORK_IDENTITY.md NI-F11).

`docs/test_vectors/EMISSION_AUTH_MSG_V1/vectors.json` pins the emission vin
fixture's framed field inventory (`expected.auth_msg_framed_hex`, fields 1-8 of
`ArchivalRewardEmissionVin::auth_msg`) and, per network and role, the 64-byte
digest the two hybrid auths sign:

    auth_msg(role) = frame("shekyl/archival-emission-auth-<role>-v4", network_id,
                           [field 1, ..., field 8])[..64]

the signing envelope's frame (§2.2, §2.6, §2.7) with `network_id` the network's
16-byte genesis-derived id at position 0 and field 8 the transaction's
`tx_signable`. The frame's input is `network_id || framed`, so the digest is
recomputed from the pinned framed bytes.
This script recomputes every digest from the framed bytes through
`stdlib_cshake.py`, which shares nothing with the Rust and is anchored before
use. It anchors the framed bytes too: hashed alone under the `-v2`
customizations, which carried no id, they must give the two digests the file
pinned before NI-F11 (written out below), so the inventory is the one that was
pinned independently of this change.

Modes: with no flag it checks the pinned digests and ids (exit 0, 1 on a
mismatch, 2 when the file has no framed bytes to check, rule 47). With
`--write` it writes `expected.auth_msgs_by_network` and `network_ids` from the
framed bytes. Run with `python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/emission_auth_msg_oracle.py [--write]
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

VECTORS = cs.ROOT / "docs/test_vectors/EMISSION_AUTH_MSG_V1/vectors.json"
CUSTOMIZATIONS = {
    "backing": b"shekyl/archival-emission-auth-backing-v4",
    "claim": b"shekyl/archival-emission-auth-claim-v4",
}

# The fixture's digests as pinned on 2026-09-14 (PL-D3), under the -v2
# customizations, before the id entered the input: the framed bytes must still
# give them.
PRIOR_V2 = {
    b"shekyl/archival-emission-auth-backing-v2": (
        "c975235c70fa6c9bd80b429e8a92f06dea988a22edb6d6af38e53d62fdb79432"
        "70947bbcd8320ca7061e0e9b6c3161fdf93dfbfc4116d208287f8d54ac73c901"
    ),
    b"shekyl/archival-emission-auth-claim-v2": (
        "dd39154467976ebd6ca98456ffde6934cbcd29adee749e8621903e7908230fbc"
        "28ceeca5dd693e9b571fe7965bc64987ed684e320d46ab5d62f8858eb338b6f5"
    ),
}


def unframe(framed: bytes) -> list[bytes]:
    """The fields of a framed inventory: each behind its u64-LE length."""
    fields, at = [], 0
    while at < len(framed):
        n = int.from_bytes(framed[at:at + 8], "little")
        fields.append(framed[at + 8:at + 8 + n])
        at += 8 + n
    if at != len(framed) or len(fields) != 8:
        sys.exit("the framed bytes are not eight length-framed fields")
    return fields


def digests(framed: bytes) -> dict:
    fields = unframe(framed)
    out = {}
    for name in cs.NETWORKS:
        nid = cs.network_id(name)
        out[name] = {
            role: cs.frame(custom, nid, fields, 64).hex()
            for role, custom in CUSTOMIZATIONS.items()
        }
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    cs.anchor()
    doc = json.loads(VECTORS.read_text())
    framed_hex = doc.get("expected", {}).get("auth_msg_framed_hex")
    if not framed_hex:
        print("the vector file has no framed bytes", file=sys.stderr)
        return 2
    framed = bytes.fromhex(framed_hex)
    for custom, pinned in PRIOR_V2.items():
        if cs.cshake256(framed, 64, s=custom).hex() != pinned:
            print(
                f"the framed bytes do not give the prior {custom.decode()} digest",
                file=sys.stderr,
            )
            return 1
    computed = digests(framed)
    ids = {name: cs.network_id(name).hex() for name in cs.NETWORKS}
    customizations = {role: custom.decode() for role, custom in CUSTOMIZATIONS.items()}
    if args.write:
        doc["customizations"] = customizations
        doc["network_ids"] = ids
        doc["expected"]["auth_msgs_by_network"] = computed
        VECTORS.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {len(cs.NETWORKS)} networks x 2 roles to {VECTORS.relative_to(cs.ROOT)}")
        return 0
    bad = []
    if doc.get("customizations") != customizations:
        bad.append("customizations")
    if doc.get("network_ids") != ids:
        bad.append("network_ids")
    if doc["expected"].get("auth_msgs_by_network") != computed:
        bad.append("expected.auth_msgs_by_network")
    if bad:
        print(f"{VECTORS.relative_to(cs.ROOT)}: not the oracle's: {', '.join(bad)}", file=sys.stderr)
        return 1
    print(
        f"emission auth oracle: framed bytes anchored on the prior pins; "
        f"{len(cs.NETWORKS)} networks x 2 roles match"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
