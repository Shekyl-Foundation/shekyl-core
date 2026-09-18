#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""RTN-7 gate: `shekyl-wire`'s public surface carries no unnamed `[u8; 32]`.

Every 32-byte chain identity leaving the wire crate is a `shekyl-types`
newtype — `TxHash`, `BlockHash`, `CurveTreeRoot`, `AttestationRoot`,
`PrefixHash`, `PqcAuthHash`, `PrunableHash`, `PCanonicalId`. What remains raw
is raw for a reason, and this gate is where the reason lives.

Without it RTN-7 is a cleanup that decays invisibly: `RAW_TYPE_NEWTYPE_MIGRATION.md`
§6 records the intent, and rows do not gate. The moment the typing lands,
nothing stops the next wire field arriving as `[u8; 32]`. Same `{item: reason}`
shape as the census bijection map, `RUST_ONLY_TABLES`, `DEFERRED_DOCS` and
`CXX_HOLDER_RE`; unnamed occurrences are red.

Red in **both** directions (rule 47):

* an occurrence on the public surface that the allowlist does not name;
* an allowlist entry whose item no longer exists — an allowlist may not
  outlive its subject, or it becomes the stale permission nobody re-reads;
* an empty scan — no `pub` items found at all means the crate moved or the
  parse broke, and absence of signal is first evidence the subject is absent.

Scope: `pub` field declarations and `pub fn` signatures in
`rust/shekyl-wire/src/**/*.rs`. `pub(crate)` and private items are not
surface: the mixers (`hash_concat`, `merkle_root`) take raw digests by
design and convert at the call.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

WIRE_SRC = Path("rust/shekyl-wire/src")

# `<file>::<item>` → why it is not a newtype. Every entry names its
# **addressee**: a reason with no owner is how `DEFERRED_DOCS`-shaped lists
# rot, and the red-when-the-item-is-gone leg cannot help an entry whose owner
# is unspecified.
ALLOWED: dict[str, str] = {
    # Curve points and scalars — transform-shaped crypto objects, deferred to
    # the crates that build and verify them (RAW_TYPE_NEWTYPE_MIGRATION.md
    # original PR E). Addressees named per RTN-7 §3.2.
    "transaction.rs::Output.key": (
        "one-time public key (curve point) — addressee shekyl-tx-builder / "
        "shekyl-scanner; #771's OneTimePubkey is minted for engine-state "
        "persistence, and adopting it at the codec is that crate pair's call"
    ),
    "transaction.rs::CtBase.commitments": (
        "Pedersen commitments (curve points) — addressee shekyl-tx-builder "
        "(CommitmentBytes, same provenance)"
    ),
    "transaction.rs::BpPlus.a": "Bulletproof+ point — addressee shekyl-proofs",
    "transaction.rs::BpPlus.b": "Bulletproof+ point — addressee shekyl-proofs",
    "transaction.rs::BpPlus.l": "Bulletproof+ point vector — addressee shekyl-proofs",
    "transaction.rs::BpPlus.r": "Bulletproof+ point vector — addressee shekyl-proofs",
    "transaction.rs::BpPlus.r1": "Bulletproof+ scalar — addressee shekyl-proofs",
    "transaction.rs::BpPlus.s1": "Bulletproof+ scalar — addressee shekyl-proofs",
    "transaction.rs::BpPlus.d1": "Bulletproof+ scalar — addressee shekyl-proofs",
    "transaction.rs::BpPlus.a1": "Bulletproof+ scalar — addressee shekyl-proofs",
    "transaction.rs::Prunable.pseudo_outs": (
        "per-input pseudo-out commitments (curve points) — addressee "
        "shekyl-tx-builder"
    ),
    "transaction.rs::Input::ToKey.key_image": (
        "key image — `shekyl_types::KeyImage` exists but is `redact, "
        "no_display`, and the wire codec's RPC projections hex-encode this "
        "field; typing it is the key-image exposure question, owned by the "
        "wallet-RPC and scanner lanes, not this gate"
    ),
    "tx_extra.rs::KemCiphertext.x25519": (
        "ephemeral X25519 KEM ciphertext — a transform-shaped crypto object, "
        "not a chain identity; addressee shekyl-crypto-pq (its KEM types)"
    ),
    # A signing preimage that is NOT a txid component, so it is not a member
    # of the component-hash family Q3 typed `prefix_hash` into.
    "transaction.rs::pqc_signing_payload_hashes()": (
        "per-input §1.5 signing payload digests — one message per "
        "`pqc_auths` entry, not a component of any txid (unlike "
        "`prefix_hash`, which is the txid's first component and so became "
        "`PrefixHash`). No component-hash family member fits, and minting "
        "one for a single consumer would be the fresh-name-for-nothing Q3 "
        "declined. Addressee: the signing lane (shekyl-tx-builder's "
        "`sign_pqc_auths`, which consumes these as messages). Reopen if a "
        "second consumer appears, or if any site can pass one where a txid "
        "component is expected"
    ),
    # An identity with no newtype and no adjacency hazard (RTN-7 Q2's
    # discriminator, written here so a later reviewer re-runs the test rather
    # than re-deriving it).
    "tx_extra.rs::PqcOwnershipEntry.group_id": (
        "multisig group id — adjacency test (could a path pass a txid, key "
        "image or component hash where a group id belongs?): it is parsed "
        "into a struct and consumed by group logic, and no site takes a bare "
        "[u8; 32] that could be either, so: low. Zero-hash for single-signer. "
        "Reopen when a second consumer appears, or when any site accepts it "
        "as a bare array beside another 32-byte value. Addressee: shekyl-multisig"
    ),
}

# A `pub` field: `pub name: <ty>` where <ty> mentions [u8; 32].
FIELD_RE = re.compile(r"^\s*pub\s+(?P<name>\w+)\s*:\s*(?P<ty>[^,\n]*\[u8;\s*32\][^,\n]*)")
# A field inside a `pub enum`'s struct variant. These carry **no `pub`
# keyword and are public anyway**, which is exactly the occurrence a
# `pub`-only scan would miss — and did, until this gate's own first run
# reported `Input::ToKey.key_image` as an allowlist entry with no subject.
VARIANT_FIELD_RE = re.compile(r"^\s+(?P<name>\w+)\s*:\s*(?P<ty>[^,\n]*\[u8;\s*32\][^,\n]*)")
# A `pub fn` whose signature line mentions [u8; 32] (params or return).
FN_RE = re.compile(r"^\s*pub\s+(?:const\s+|async\s+)?fn\s+(?P<name>\w+)")
# `pub struct Name {` / `pub enum Name {` — the enclosing item for a field.
ITEM_RE = re.compile(r"^\s*pub\s+(?P<kind>struct|enum)\s+(?P<name>\w+)")
# An enum variant's struct body: `Variant {`
VARIANT_RE = re.compile(r"^\s{4}(?P<name>[A-Z]\w*)\s*\{")


def scan(root: Path) -> tuple[dict[str, str], int]:
    """Return (occurrence → source line, count of `pub` items seen)."""
    found: dict[str, str] = {}
    pub_items = 0
    for path in sorted(root.rglob("*.rs")):
        rel = str(path.relative_to(root))
        enclosing = "?"
        variant = None
        in_enum = False
        for line in path.read_text().splitlines():
            if m := ITEM_RE.match(line):
                enclosing, variant = m.group("name"), None
                in_enum = m.group("kind") == "enum"
                pub_items += 1
                continue
            if m := VARIANT_RE.match(line):
                variant = m.group("name")
            if FN_RE.match(line):
                pub_items += 1
            if "[u8; 32]" not in line and "[u8;32]" not in line:
                continue
            if m := FIELD_RE.match(line) or (in_enum and VARIANT_FIELD_RE.match(line)):
                where = f"{enclosing}::{variant}" if variant else enclosing
                found[f"{rel}::{where}.{m.group('name')}"] = line.strip()
            elif m := FN_RE.match(line):
                found[f"{rel}::{m.group('name')}()"] = line.strip()
    return found, pub_items


def check(root: Path, allowed: dict[str, str]) -> list[str]:
    found, pub_items = scan(root)
    problems: list[str] = []
    if pub_items == 0:
        problems.append(
            f"no `pub` items found under {root} — the crate moved or this "
            f"gate's parser broke; absence of signal is first evidence the "
            f"subject is absent (rule 47)"
        )
        return problems
    for item, line in sorted(found.items()):
        if item not in allowed:
            problems.append(
                f"{item}: raw `[u8; 32]` on the public wire surface with no "
                f"allowlist entry — use the `shekyl-types` newtype (RTN-7), "
                f"or add an entry naming the reason and its addressee crate.\n"
                f"    {line}"
            )
    for item in sorted(allowed):
        if item not in found:
            problems.append(
                f"{item}: allowlisted but no longer present — delete the entry. "
                f"An allowlist may not outlive its subject."
            )
    return problems


def selftest() -> int:
    """Each leg fires on its own axis, and the clean tree passes."""
    failures = 0

    def expect(name: str, problems: list[str], want: str | None) -> None:
        nonlocal failures
        got = "\n".join(problems)
        if want is None:
            if problems:
                print(f"SELFTEST {name}: expected clean, got:\n{got}")
                failures += 1
        elif want not in got:
            print(f"SELFTEST {name}: expected {want!r} in:\n{got or '(clean)'}")
            failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "block.rs").write_text(
            "pub struct BlockHeader {\n"
            "    pub previous: BlockHash,\n"
            "}\n"
            "impl BlockHeader {\n"
            "    pub fn hash(&self) -> BlockHash {}\n"
            "}\n"
        )
        expect("clean tree", check(root, {}), None)

        (root / "block.rs").write_text(
            "pub struct BlockHeader {\n    pub previous: [u8; 32],\n}\n"
            "pub fn unrelated() {}\n"
        )
        expect("raw field", check(root, {}), "block.rs::BlockHeader.previous")
        expect(
            "raw field allowlisted",
            check(root, {"block.rs::BlockHeader.previous": "reason; addressee X"}),
            None,
        )

        (root / "block.rs").write_text(
            "pub struct Block {\n    pub ok: BlockHash,\n}\n"
            "pub fn hash(&self) -> [u8; 32] {}\n"
        )
        expect("raw return", check(root, {}), "block.rs::hash()")

        # The gap this gate's own first run exposed: an enum variant's fields
        # are public with no `pub` keyword, so a `pub`-only scan misses them.
        (root / "block.rs").write_text(
            "pub enum Input {\n"
            "    Gen(u64),\n"
            "    ToKey {\n"
            "        key_image: [u8; 32],\n"
            "    },\n"
            "}\n"
        )
        expect(
            "enum variant field",
            check(root, {}),
            "block.rs::Input::ToKey.key_image",
        )

        (root / "block.rs").write_text("pub struct Block {\n    pub ok: BlockHash,\n}\n")
        expect(
            "stale allowlist entry",
            check(root, {"block.rs::Gone.field": "reason"}),
            "no longer present",
        )

    with tempfile.TemporaryDirectory() as tmp:
        expect("empty scan", check(Path(tmp), {}), "no `pub` items found")

    print("OK: self-tests pass" if not failures else f"{failures} self-test failure(s)")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if not WIRE_SRC.is_dir():
        print(f"FAIL: {WIRE_SRC} not found — run from the repository root")
        return 2
    problems = check(WIRE_SRC, ALLOWED)
    if problems:
        print("FAIL: the wire crate's public surface has unnamed raw hashes\n")
        for p in problems:
            print(f"  - {p}")
        print(
            "\nRTN-7: a 32-byte chain identity leaves `shekyl-wire` as a "
            "`shekyl-types` newtype. See docs/completed/RTN_7_WIRE_HASH_TYPES.md §4."
        )
        return 1
    found, pub_items = scan(WIRE_SRC)
    print(
        f"OK: {pub_items} public items scanned; "
        f"{len(found)} raw `[u8; 32]` occurrence(s), all {len(ALLOWED)} allowlisted "
        f"with a named addressee."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
