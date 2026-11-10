# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the multisig address fingerprint (NETWORK_IDENTITY.md NI-R15).

`docs/test_vectors/MULTISIG_FINGERPRINT_V3.json` pins, per network, the
fingerprint of one fixed 2-of-2 group payload (the signing envelope §2.6):

    fingerprint = frame("shekyl/multisig-address-v3", name_id, [canonical payload])

with `name_id` the network's 16-byte name binding,
cSHAKE256(S = "shekyl/network-name-v1", X = "shekyl/<network>")[..16]. The
canonical payload (address version 0x02, `multisig_address.rs`) is
`version(1) || group_version(1) || spend_auth_version(1) || network_code(1) ||
n(1) || m(1) || B(32) || Y(32) || group_kem_pk(1216) || kem_pk[0] || kem_pk[1]`,
built here from the fixture's values. Before trusting that builder, this script
checks its shared parts against the `-v1` fingerprint pinned before the name
entered: the version 0x01 layout (no group KEM key), mainnet, hashed alone
under `shekyl/multisig-address-v1`. The version 0x02 payload differs from it
only by the version byte and the inserted group key. The hash goes through
`stdlib_cshake.py`, which shares nothing with the Rust and is anchored before
use.

Modes: with no flag it checks the pinned file (exit 0, 1 on a mismatch, 2 when
it pins no fingerprint, rule 47). With `--write` it writes the file. Run with
`python3 -I`; stdlib only.

Usage: python3 -I scripts/kat/multisig_fingerprint_oracle.py [--write]
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

VECTORS = cs.ROOT / "docs/test_vectors/MULTISIG_FINGERPRINT_V3.json"
CUSTOMIZATION = b"shekyl/multisig-address-v3"
PRIOR_V1_CUSTOMIZATION = b"shekyl/multisig-address-v1"
# The mainnet fixture's fingerprint as pinned before NI-R15 (multisig_address.rs).
PRIOR_V1_MAINNET = "ed49a839c9ef73911770ac15cd5b1110d08bebf6b3e7d9d6f2ed3ac9661f6f2e"

# The network's numeric code (Network::code) and name tag (Network::tag), written out.
CODES = {"mainnet": 0, "testnet": 1, "stagenet": 2, "regtest": 3}
HYBRID_KEM_PUBKEY_LEN = 1216
MULTISIG_ADDRESS_VERSION, GROUP_VERSION, SPEND_AUTH_VERSION = 2, 1, 2
N, M = 2, 2
B_GROUP, Y_GROUP = b"\xb1" * 32, b"\x71" * 32
GROUP_KEM = b"\xc0" * HYBRID_KEM_PUBKEY_LEN


def _payload(version: int, name: str, group_kem: bytes) -> bytes:
    header = bytes([version, GROUP_VERSION, SPEND_AUTH_VERSION, CODES[name], N, M])
    kems = b"".join(bytes([i]) * HYBRID_KEM_PUBKEY_LEN for i in range(N))
    return header + B_GROUP + Y_GROUP + group_kem + kems


def payload(name: str) -> bytes:
    """The version 0x02 payload the vectors pin."""
    return _payload(MULTISIG_ADDRESS_VERSION, name, GROUP_KEM)


def prior_v1_payload(name: str) -> bytes:
    """The version 0x01 layout the anchor was pinned over: no group KEM key."""
    return _payload(1, name, b"")


def fingerprint(name: str) -> str:
    return cs.frame(CUSTOMIZATION, cs.name_id(name), [payload(name)]).hex()


def build() -> dict:
    return {
        "description": (
            "Multisig address fingerprints (NETWORK_IDENTITY.md NI-R15; the signing "
            "envelope §2.6): frame(shekyl/multisig-address-v3, name_id, [canonical "
            "payload]), name_id the network's name binding, for one fixed 2-of-2 address "
            "version 0x02 payload (B = 0xB1 x32, Y = 0x71 x32, group KEM key = 0xC0 x1216, "
            "member KEM key i = byte i x1216) on each network. "
            "Written and checked by scripts/kat/multisig_fingerprint_oracle.py; read by "
            "shekyl-address's address_fingerprint_kat."
        ),
        "customization": CUSTOMIZATION.decode(),
        "fingerprints": {name: fingerprint(name) for name in cs.NETWORKS},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    cs.anchor()
    if cs.cshake256(prior_v1_payload("mainnet"), 32, s=PRIOR_V1_CUSTOMIZATION).hex() != PRIOR_V1_MAINNET:
        print("the payload builder does not reproduce the prior -v1 pin", file=sys.stderr)
        return 1
    computed = build()
    if args.write:
        VECTORS.write_text(json.dumps(computed, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {len(cs.NETWORKS)} fingerprints to {VECTORS.relative_to(cs.ROOT)}")
        return 0
    pinned = json.loads(VECTORS.read_text())
    if not pinned.get("fingerprints"):
        print("the vector file pins no fingerprint", file=sys.stderr)
        return 2
    if pinned != computed:
        print(f"{VECTORS.relative_to(cs.ROOT)} is not the oracle's", file=sys.stderr)
        return 1
    print(
        f"multisig fingerprint oracle: payload anchored on the prior pin; "
        f"{len(cs.NETWORKS)} networks match"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
