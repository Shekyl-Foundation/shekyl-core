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
nothing stops the next wire field arriving as `[u8; 32]`. The allowlist is
`dict[str, Allow]` with `Allow(reason, addressee)` as two fields — the same
named-exception shape as the census bijection map, `RUST_ONLY_TABLES`,
`DEFERRED_DOCS` and `CXX_HOLDER_RE`; unnamed occurrences are red.

Red in **both** directions (rule 47):

* an occurrence on the public surface that the allowlist does not name;
* an allowlist entry whose item no longer exists — an allowlist may not
  outlive its subject, or it becomes the stale permission nobody re-reads;
* an allowlist entry with an empty reason or no addressee — the success
  line claims every occurrence has a named owner, so the gate asserts it;
* an empty scan — no `pub` items found at all means the crate moved or the
  parse broke, and absence of signal is first evidence the subject is absent.

Scope — the **public** surface of `rust/shekyl-wire/src/**/*.rs`. A
declaration is one item even when rustfmt wraps it, so every kind of
surface is buffered to its terminator and then searched as a whole:

* `pub` struct fields — from `pub name:` through a complete type
  (bracket depth back to zero). Completeness is depth, not a trailing
  comma: the last field of a struct has none, and `Vec<\n [u8; 32],\n>`
  is one field, not three lines;
* fields of a `pub enum`'s struct variants and the payloads of its tuple
  variants (both public with **no `pub` keyword** — a `pub`-only scan
  misses them, and this gate's own first run did), buffered the same way;
* `pub fn` signatures — from the `fn` line to the body's `{` (or a trait
  method's `;`).

`pub(crate)` and private items are not surface: the mixers (`hash_concat`,
`merkle_root`) take raw digests by design and convert at the call.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

WIRE_SRC = Path("rust/shekyl-wire/src")


class Allow(NamedTuple):
    """Why a public `[u8; 32]` stays raw, and **who owns typing it**.

    The addressee is a field, not a phrase inside the reason, so the gate can
    check it exists: a cause with no owner is how `DEFERRED_DOCS`-shaped lists
    rot, and the red-when-the-item-is-gone leg cannot help an entry whose
    owner is unspecified (RTN-7 Q4). The success line's claim that every
    occurrence has a named addressee is asserted by `check`, not assumed.
    """

    reason: str
    addressee: str


# `<file>::<item>` → why it is not a newtype, and whose it is.
ALLOWED: dict[str, Allow] = {
    # Curve points and scalars — transform-shaped crypto objects, deferred to
    # the crates that build and verify them (RAW_TYPE_NEWTYPE_MIGRATION.md
    # original PR E). Addressees per RTN-7 §3.2.
    "transaction.rs::Output.key": Allow(
        "one-time public key (curve point); #771's OneTimePubkey is minted for "
        "engine-state persistence, and adopting it at the codec is the "
        "derivation/match sites' call",
        "shekyl-tx-builder / shekyl-scanner",
    ),
    "transaction.rs::CtBase.commitments": Allow(
        "Pedersen commitments (curve points); CommitmentBytes, same provenance",
        "shekyl-tx-builder",
    ),
    "transaction.rs::BpPlus.a": Allow("Bulletproof+ point", "shekyl-proofs"),
    "transaction.rs::BpPlus.b": Allow("Bulletproof+ point", "shekyl-proofs"),
    "transaction.rs::BpPlus.l": Allow("Bulletproof+ point vector", "shekyl-proofs"),
    "transaction.rs::BpPlus.r": Allow("Bulletproof+ point vector", "shekyl-proofs"),
    "transaction.rs::BpPlus.r1": Allow("Bulletproof+ scalar", "shekyl-proofs"),
    "transaction.rs::BpPlus.s1": Allow("Bulletproof+ scalar", "shekyl-proofs"),
    "transaction.rs::BpPlus.d1": Allow("Bulletproof+ scalar", "shekyl-proofs"),
    "transaction.rs::BpPlus.a1": Allow("Bulletproof+ scalar", "shekyl-proofs"),
    "transaction.rs::Prunable.pseudo_outs": Allow(
        "per-input pseudo-out commitments (curve points)", "shekyl-tx-builder"
    ),
    # The codec is `tx_extra/mod.rs` (directory module, 2026-09-23). The
    # rulings are unchanged: these are curve points and a KEM ciphertext,
    # not chain identities.
    "tx_extra/mod.rs::TxExtraField::PubKey.0": Allow(
        "the transaction public key R (curve point) in tx_extra 0x01 — the "
        "same class as Output.key; the scanner-side derivation is what would "
        "consume a newtype for it",
        "shekyl-tx-builder / shekyl-scanner",
    ),
    "tx_extra/mod.rs::TxExtraField::AdditionalPubKeys.0": Allow(
        "additional per-output tx public keys (curve points) in tx_extra 0x04; "
        "one class with PubKey",
        "shekyl-tx-builder / shekyl-scanner",
    ),
    "tx_extra/mod.rs::KemCiphertext.x25519": Allow(
        "ephemeral X25519 KEM ciphertext — a transform-shaped crypto object, "
        "not a chain identity",
        "shekyl-crypto-pq",
    ),
    "transaction.rs::Input::ToKey.key_image": Allow(
        "key image — `shekyl_types::KeyImage` exists but is `redact, "
        "no_display`, and the wire codec's RPC projections hex-encode this "
        "field; typing it is the key-image exposure question, not this gate's",
        "shekyl-wallet-rpc / shekyl-scanner",
    ),
    # A signing preimage that is NOT a txid component, so it is not a member
    # of the component-hash family Q3 typed `prefix_hash` into.
    "transaction.rs::pqc_signing_payload_hashes()": Allow(
        "per-input §1.5 signing payload digests — one message per `pqc_auths` "
        "entry, not a component of any txid (unlike `prefix_hash`, which is the "
        "txid's first component and so became `PrefixHash`). No component-hash "
        "family member fits, and minting one for a single consumer would be the "
        "fresh-name-for-nothing Q3 declined. Reopen if a second consumer "
        "appears, or if any site can pass one where a txid component is expected",
        "shekyl-tx-builder (sign_pqc_auths consumes these as messages)",
    ),
    # `tx_extra.rs::PqcOwnershipEntry.group_id` was allowlisted here (RTN-7
    # Q2's adjacency discriminator); the cell was deleted with tag 0x05
    # (REJECTED 2026-09-22, PQC_MULTISIG.md §7.4 "Retired tag"), and an
    # allowlist may not outlive its subject.
}

RAW = re.compile(r"\[u8;\s*32\]")
# Declaration *starts*. The type may wrap; the scanner buffers until the
# type is complete (fields, tuple variants) or the body opens (fns).
# `pub(crate)` / `pub(super)` fail FIELD_START — `(crate)` is not an ident.
FIELD_START_RE = re.compile(r"^\s*pub\s+(?P<name>\w+)\s*:")
VARIANT_FIELD_START_RE = re.compile(r"^\s+(?P<name>\w+)\s*:")
TUPLE_VARIANT_START_RE = re.compile(r"^\s{4}(?P<name>[A-Z]\w*)\(")
FN_RE = re.compile(r"^\s*pub\s+(?:const\s+|async\s+|unsafe\s+)?fn\s+(?P<name>\w+)")
# A method inside a `pub trait`'s body. Trait methods are written without
# `pub` and are public anyway — the third "public with no keyword" surface
# after enum struct-variant fields and tuple-variant payloads.
TRAIT_FN_RE = re.compile(r"^\s{4}(?:unsafe\s+|async\s+)?fn\s+(?P<name>\w+)")
ITEM_RE = re.compile(r"^\s*pub\s+(?P<kind>struct|enum|trait)\s+(?P<name>\w+)")
VARIANT_RE = re.compile(r"^\s{4}(?P<name>[A-Z]\w*)\s*\{")
# A top-level `}` closes the enclosing item, so a bare `fn` after a trait
# body is an impl's, not a trait method's.
ITEM_END_RE = re.compile(r"^\}")

# One pending kind per surface: a fn waits for `{`/`;`, a field waits for
# a complete type, a tuple variant waits for its closing paren.
_KIND_FN = "fn"
_KIND_FIELD = "field"
_KIND_TUPLE = "tuple"


def signature_ends(line: str) -> bool:
    return "{" in line or line.rstrip().endswith(";")


def _joined(lines: list[str]) -> str:
    return " ".join(part.strip() for part in lines)


def _nesting_depth(text: str) -> int:
    """Net unmatched `<([` openers. Types, not expressions; comments ignored."""
    depth = 0
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(depth - 1, 0)
    return depth


def field_declaration_complete(joined: str) -> bool:
    """True once the type after `name:` has closed.

    Completeness is bracket depth, not a trailing comma. rustfmt wraps
    `Vec<[u8; 32]>` across lines, and the last field of a struct has no
    comma; either hole made a line-regex report green.
    """
    _, sep, ty = joined.partition(":")
    if not sep or not ty.strip():
        return False
    depth = 0
    for ch in ty:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(depth - 1, 0)
        elif ch in ",}" and depth == 0:
            return True
    return depth == 0


def tuple_variant_complete(joined: str) -> bool:
    start = joined.find("(")
    if start < 0:
        return False
    return _nesting_depth(joined[start:]) == 0


def pending_complete(lines: list[str], kind: str) -> bool:
    if kind == _KIND_FN:
        return signature_ends(lines[-1])
    joined = _joined(lines)
    if kind == _KIND_FIELD:
        return field_declaration_complete(joined)
    if kind == _KIND_TUPLE:
        return tuple_variant_complete(joined)
    return False


def scan(root: Path) -> tuple[dict[str, str], int]:
    """Return (occurrence → source text, count of `pub` items seen)."""
    found: dict[str, str] = {}
    pub_items = 0
    for path in sorted(root.rglob("*.rs")):
        rel = str(path.relative_to(root))
        enclosing = "?"
        variant = None
        in_enum = False
        in_trait = False
        pending: list[str] | None = None
        pending_kind = ""
        pending_key = ""

        def flush() -> None:
            nonlocal pending
            if pending is None:
                return
            joined = _joined(pending)
            if RAW.search(joined):
                found[pending_key] = joined
            pending = None

        def take(kind: str, key: str, line: str) -> None:
            nonlocal pending, pending_kind, pending_key
            pending_kind, pending_key, pending = kind, key, [line]
            if pending_complete(pending, pending_kind):
                flush()

        for line in path.read_text().splitlines():
            if pending is not None:
                pending.append(line)
                if pending_complete(pending, pending_kind):
                    flush()
                continue
            if m := ITEM_RE.match(line):
                enclosing, variant = m.group("name"), None
                in_enum = m.group("kind") == "enum"
                in_trait = m.group("kind") == "trait"
                pub_items += 1
                continue
            if ITEM_END_RE.match(line):
                in_enum = in_trait = False
                continue
            if m := FN_RE.match(line):
                pub_items += 1
                take(_KIND_FN, f"{rel}::{m.group('name')}()", line)
                continue
            if in_trait and (m := TRAIT_FN_RE.match(line)):
                pub_items += 1
                take(_KIND_FN, f"{rel}::{enclosing}::{m.group('name')}()", line)
                continue
            if m := VARIANT_RE.match(line):
                variant = m.group("name")
                continue
            if in_enum and (m := TUPLE_VARIANT_START_RE.match(line)):
                take(
                    _KIND_TUPLE,
                    f"{rel}::{enclosing}::{m.group('name')}.0",
                    line,
                )
                continue
            field = FIELD_START_RE.match(line)
            if field is None and in_enum and variant:
                field = VARIANT_FIELD_START_RE.match(line)
            if field:
                where = f"{enclosing}::{variant}" if variant else enclosing
                take(_KIND_FIELD, f"{rel}::{where}.{field.group('name')}", line)
        flush()
    return found, pub_items


def check(root: Path, allowed: dict[str, Allow]) -> list[str]:
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
    for item, allow in sorted(allowed.items()):
        if item not in found:
            problems.append(
                f"{item}: allowlisted but no longer present — delete the entry. "
                f"An allowlist may not outlive its subject."
            )
        if not allow.reason.strip():
            problems.append(f"{item}: allowlist entry has an empty reason.")
        if not allow.addressee.strip():
            problems.append(
                f"{item}: allowlist entry names no addressee — a cause with no "
                f"owner is how these lists rot (RTN-7 Q4)."
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

    ok = Allow("a reason", "shekyl-somewhere")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "block.rs"

        src.write_text(
            "pub struct BlockHeader {\n"
            "    pub previous: BlockHash,\n"
            "}\n"
            "impl BlockHeader {\n"
            "    pub fn hash(&self) -> BlockHash {}\n"
            "}\n"
        )
        expect("clean tree", check(root, {}), None)

        src.write_text(
            "pub struct BlockHeader {\n    pub previous: [u8; 32],\n}\n"
            "pub fn unrelated() {}\n"
        )
        expect("raw field", check(root, {}), "block.rs::BlockHeader.previous")
        expect(
            "raw field allowlisted",
            check(root, {"block.rs::BlockHeader.previous": ok}),
            None,
        )
        # The allowlist's own invariant: an entry must carry a reason and an
        # owner, or the success line would claim what nothing checked.
        expect(
            "empty addressee",
            check(root, {"block.rs::BlockHeader.previous": Allow("a reason", "  ")}),
            "names no addressee",
        )
        expect(
            "empty reason",
            check(root, {"block.rs::BlockHeader.previous": Allow("", "shekyl-x")}),
            "empty reason",
        )

        src.write_text(
            "pub struct Block {\n    pub ok: BlockHash,\n}\n"
            "pub fn hash(&self) -> [u8; 32] {}\n"
        )
        expect("raw return", check(root, {}), "block.rs::hash()")

        # A multi-line signature puts the raw type on a line that does not
        # say `pub fn`; a single-line check passes it.
        src.write_text(
            "pub struct Block {\n    pub ok: BlockHash,\n}\n"
            "pub fn reconstruct(\n"
            "    &self,\n"
            "    supplied: [u8; 32],\n"
            ") -> TxHash {\n"
            "}\n"
        )
        expect("multi-line signature", check(root, {}), "block.rs::reconstruct()")

        # rustfmt wraps a field type; a line-regex sees `[u8; 32]` on a
        # line with no `name:` and reports green. Completeness is depth,
        # not a comma — the last field of a struct has none.
        src.write_text(
            "pub struct Header {\n"
            "    pub digest: Vec<\n"
            "        [u8; 32],\n"
            "    >,\n"
            "}\n"
        )
        expect("multi-line field", check(root, {}), "block.rs::Header.digest")
        expect(
            "multi-line field allowlisted",
            check(root, {"block.rs::Header.digest": ok}),
            None,
        )
        src.write_text(
            "pub struct Header {\n"
            "    pub digest: Vec<\n"
            "        [u8; 32]\n"
            "    >\n"
            "}\n"
        )
        expect("multi-line field, no comma", check(root, {}), "block.rs::Header.digest")
        src.write_text(
            "pub enum Input {\n"
            "    ToKey {\n"
            "        key_image: Vec<\n"
            "            [u8; 32],\n"
            "        >,\n"
            "    },\n"
            "}\n"
        )
        expect(
            "multi-line enum field",
            check(root, {}),
            "block.rs::Input::ToKey.key_image",
        )
        src.write_text(
            "pub enum TxExtraField {\n"
            "    PubKey(\n"
            "        [u8; 32],\n"
            "    ),\n"
            "}\n"
        )
        expect(
            "multi-line tuple variant",
            check(root, {}),
            "block.rs::TxExtraField::PubKey.0",
        )

        # An enum variant's fields are public with no `pub` keyword.
        src.write_text(
            "pub enum Input {\n"
            "    Gen(u64),\n"
            "    ToKey {\n"
            "        key_image: [u8; 32],\n"
            "    },\n"
            "}\n"
        )
        expect("enum struct-variant field", check(root, {}), "block.rs::Input::ToKey.key_image")

        # So are a tuple variant's payloads — `PubKey([u8; 32])`.
        src.write_text(
            "pub enum TxExtraField {\n"
            "    Padding(usize),\n"
            "    PubKey([u8; 32]),\n"
            "    AdditionalPubKeys(Vec<[u8; 32]>),\n"
            "}\n"
        )
        problems = check(root, {})
        expect("tuple variant", problems, "block.rs::TxExtraField::PubKey.0")
        expect("tuple variant (vec)", problems, "block.rs::TxExtraField::AdditionalPubKeys.0")

        # Trait methods are the third keyword-less public surface: written
        # `fn`, public through the `pub trait`. A `fn` after the trait's
        # closing brace is an impl's and is not surface.
        src.write_text(
            "pub trait Digest: Copy {\n"
            "    fn digest(&self) -> [u8; 32];\n"
            "    fn wide(\n"
            "        &self,\n"
            "    ) -> Vec<[u8; 32]>;\n"
            "}\n"
            "impl Digest for Thing {\n"
            "    fn digest(&self) -> [u8; 32] {}\n"
            "}\n"
        )
        problems = check(root, {})
        expect("trait method", problems, "block.rs::Digest::digest()")
        expect("trait method (multi-line)", problems, "block.rs::Digest::wide()")
        expect(
            "impl fn is not surface",
            [p for p in problems if "Thing" in p or p.count("digest()") > 1],
            None,
        )

        # Not surface: pub(crate) fields and fns are not scanned.
        src.write_text(
            "pub struct Mixer {\n    pub(crate) digest: [u8; 32],\n}\n"
            "pub(crate) fn hash_concat(parts: &[[u8; 32]]) -> [u8; 32] {}\n"
            "pub fn keep_the_scan_non_empty() {}\n"
        )
        expect("pub(crate) is not surface", check(root, {}), None)

        src.write_text("pub struct Block {\n    pub ok: BlockHash,\n}\n")
        expect(
            "stale allowlist entry",
            check(root, {"block.rs::Gone.field": ok}),
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
        f"with a reason and a named addressee (checked)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
