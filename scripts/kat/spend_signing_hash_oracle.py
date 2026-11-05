# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for a transaction's network-bound message and the spend
signature's hash (the signing envelope §2.2; NETWORK_IDENTITY.md NI-Q4, NI-F12).

`rust/shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json` carries, for
each pinned transaction, the per-input signing payloads the C++ assembly
produced before it was deleted:

    payload(i) = pruned ‖ prunable_hash ‖ header(i) ‖ key_hashes
    pruned     = varint(version) ‖ prefix ‖ base

Those captured bytes hold every field the envelope frames. This script takes
them apart without any help from the Rust, then computes

    tx_signable    = frame("shekyl/tx-signable-v1", id,
                           [keccak256(varint(version) ‖ prefix), keccak256(base)])
    signed_hash(i) = frame("shekyl/fcmp-spend-signing-v2", id,
                           [tx_signable, header(i), key_hashes, prunable_hash])[..64]

(the spend hash is 64 bytes, a hybrid signature's signed content; the signing
envelope §2.7)

on each network, through `stdlib_cshake.py` (Keccak, cSHAKE256 and `frame`
written from the specifications, anchored on published samples before use).

Taking the payload apart:
- `key_hashes` is the last 32·n bytes, n the number of payloads (one per auth).
- `header(i)` is self-delimiting from its start: auth_version, scheme_id,
  flags (u16 LE), varint(len), the public key. The pruned length P is the one
  for which the header that starts at P + 32 ends exactly where key_hashes
  begin, in every payload, with `payload[:P + 32]` common to all of them.
  The transaction's own bytes confirm it: they start with those P bytes, the
  n auths that follow parse exactly, and the prunable region after them
  hashes to the payload's prunable_hash.
- `base` is self-delimiting from its start: CT_TYPE_FCMP (0x01), varint(fee),
  the 32-byte reference block, then 50 bytes per output (9-byte encrypted
  amount, 9-byte encrypted label, 32-byte commitment). The prefix length s is
  the one for which the base that starts at s ends exactly at P with k
  outputs, and the prefix's tail is varint(k), k outputs (varint(amount),
  0x00, key, view tag) and the length-prefixed extra, ending exactly at s.
Either split must be unique, or the oracle stops: it never guesses.

Modes: with no flag it checks that every pinned `tx_signable_by_network` and
`signed_hashes_by_network` entry is what it computes (exit 0, or 1 on a
mismatch, or 2 when the fixture lacks a subject this oracle exists to check or
a payload does not take apart, rule 47). With `--write` it writes those
entries into the fixture. Run with `python3 -I`; stdlib only.

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
TX_SIGNABLE_DST = b"shekyl/tx-signable-v1"
SPEND_SIGNING_DST = b"shekyl/fcmp-spend-signing-v2"
CT_TYPE_FCMP = 0x01
OUTPUT_BASE_BYTES = 9 + 9 + 32


class Unparsed(Exception):
    pass


def varint(data: bytes, at: int) -> tuple[int, int] | None:
    """A canonical LEB128 varint at `at`: (value, end), or None."""
    value = shift = 0
    for i in range(at, min(at + 10, len(data))):
        byte = data[i]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if byte == 0 and i > at:
                return None  # a non-canonical trailing zero byte
            return value, i + 1
        shift += 7
    return None


def header_end(payload: bytes, at: int) -> int | None:
    if at + 4 > len(payload):
        return None
    got = varint(payload, at + 4)
    if got is None:
        return None
    length, key_at = got
    return key_at + length


def base_outputs(pruned: bytes, at: int) -> int | None:
    """The output count of a base that starts at `at` and ends where
    `pruned` does, or None."""
    if pruned[at] != CT_TYPE_FCMP:
        return None
    got = varint(pruned, at + 1)
    if got is None:
        return None
    _fee, ref_at = got
    rest = len(pruned) - (ref_at + 32)
    if rest <= 0 or rest % OUTPUT_BASE_BYTES:
        return None
    return rest // OUTPUT_BASE_BYTES


def outputs_then_extra_end_at(prefix: bytes, end: int, count: int) -> bool:
    """Whether the prefix's tail is `varint(count) ‖ count outputs ‖
    varint(len) ‖ extra(len)` ending exactly at `end`. An output is
    varint(amount) ‖ 0x00 ‖ key (32) ‖ view tag (1)."""
    for start in range(end):
        got = varint(prefix, start)
        if got is None or got[0] != count:
            continue
        at = got[1]
        for _ in range(count):
            amount = varint(prefix, at)
            if amount is None or amount[1] + 34 > end or prefix[amount[1]] != 0x00:
                at = None
                break
            at = amount[1] + 34
        if at is None:
            continue
        extra = varint(prefix, at)
        if extra is not None and extra[1] + extra[0] == end:
            return True
    return False


def auths_end(tx: bytes, at: int, count: int) -> int | None:
    """Where `count` pqc_auths starting at `at` end: each is a header then
    varint(len) ‖ signature."""
    for _ in range(count):
        end = header_end(tx, at)
        if end is None:
            return None
        got = varint(tx, end)
        if got is None:
            return None
        at = got[1] + got[0]
        if at > len(tx):
            return None
    return at


def take_apart(
    tx: bytes, payloads: list[bytes]
) -> tuple[bytes, bytes, bytes, list[bytes], bytes]:
    """(prefix, base, prunable_hash, headers, key_hashes) from the payloads,
    cross-checked against the transaction's own bytes: they start with the
    pruned segment, the auths follow it, and the prunable region after them
    hashes to the payload's prunable_hash."""
    n = len(payloads)
    key_hashes = payloads[0][-32 * n:]
    if any(p[-32 * n:] != key_hashes for p in payloads):
        raise Unparsed("the payloads disagree on key_hashes")

    def prunable_follows(pl: int) -> bool:
        end = auths_end(tx, pl, n)
        return end is not None and cs.keccak256(tx[end:]) == payloads[0][pl:pl + 32]

    shortest = min(len(p) for p in payloads)
    pruned_lens = [
        pl for pl in range(1, shortest - 32 * n - 32)
        if all(p[:pl + 32] == payloads[0][:pl + 32] for p in payloads)
        and all(header_end(p, pl + 32) == len(p) - 32 * n for p in payloads)
        and tx[:pl] == payloads[0][:pl]
        and prunable_follows(pl)
    ]
    if len(pruned_lens) != 1:
        raise Unparsed(f"{len(pruned_lens)} candidate pruned lengths")
    pl = pruned_lens[0]
    pruned = payloads[0][:pl]
    prefix_lens = [
        s for s in range(1, pl)
        if (k := base_outputs(pruned, s)) is not None
        and outputs_then_extra_end_at(pruned, s, k)
    ]
    if len(prefix_lens) != 1:
        raise Unparsed(f"{len(prefix_lens)} candidate prefix lengths")
    s = prefix_lens[0]
    prunable_hash = payloads[0][pl:pl + 32]
    headers = [p[pl + 32:len(p) - 32 * n] for p in payloads]
    return pruned[:s], pruned[s:], prunable_hash, headers, key_hashes


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
        signable: dict[str, str] = {}
        hashes: dict[str, list[str]] = {}
        if payloads:
            try:
                prefix, base, prunable_hash, headers, key_hashes = take_apart(
                    bytes.fromhex(tx["tx_hex"]), payloads
                )
            except Unparsed as e:
                print(f"{tx.get('name')}: the payloads do not take apart: {e}", file=sys.stderr)
                return 2
            fields = [cs.keccak256(prefix), cs.keccak256(base)]
            for name in cs.NETWORKS:
                tx_signable = cs.frame(TX_SIGNABLE_DST, ids[name], fields)
                signable[name] = tx_signable.hex()
                hashes[name] = [
                    cs.frame(SPEND_SIGNING_DST, ids[name],
                             [tx_signable, h, key_hashes, prunable_hash], 64).hex()
                    for h in headers
                ]
        else:
            hashes = {name: [] for name in cs.NETWORKS}
        if args.write:
            tx["tx_signable_by_network"] = signable
            tx["signed_hashes_by_network"] = hashes
        elif tx.get("tx_signable_by_network") != signable or tx.get("signed_hashes_by_network") != hashes:
            print(f"{tx.get('name')}: the pinned envelope values are not the oracle's", file=sys.stderr)
            mismatches += 1
    if args.write:
        FIXTURE.write_text(json.dumps(doc, indent=4, ensure_ascii=False) + "\n")
        print(f"wrote tx_signable_by_network and signed_hashes_by_network for {len(transactions)} transactions")
        return 0
    if mismatches:
        return 1
    print(
        f"spend signing hash oracle: {len(with_payloads)} transactions, "
        f"{sum(len(t['payloads_hex']) for t in with_payloads)} payloads x "
        f"{len(cs.NETWORKS)} networks match"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
