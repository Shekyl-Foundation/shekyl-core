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
* an allowlist entry with an empty reason or no addressee — the success
  line claims every occurrence has a named owner, so the gate asserts it;
* an empty scan — no `pub` items found at all means the crate moved or the
  parse broke, and absence of signal is first evidence the subject is absent.

Scope — the **public** surface of `rust/shekyl-wire/src/**/*.rs`:

* `pub` struct fields;
* fields of a `pub enum`'s struct variants and the payloads of its tuple
  variants (both public with **no `pub` keyword** — a `pub`-only scan misses
  them, and this gate's own first run did);
* `pub fn` signatures in full — buffered from the `fn` line to the body's
  `{`, because a multi-line signature puts the raw type on a line that does
  not say `pub fn`.

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
    "tx_extra.rs::TxExtraField::PubKey.0": Allow(
        "the transaction public key R (curve point) in tx_extra 0x01 — the "
        "same class as Output.key; the scanner-side derivation is what would "
        "consume a newtype for it",
        "shekyl-tx-builder / shekyl-scanner",
    ),
    "tx_extra.rs::TxExtraField::AdditionalPubKeys.0": Allow(
        "additional per-output tx public keys (curve points) in tx_extra 0x04; "
        "one class with PubKey",
        "shekyl-tx-builder / shekyl-scanner",
    ),
    "tx_extra.rs::KemCiphertext.x25519": Allow(
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
    # An identity with no newtype and no adjacency hazard (RTN-7 Q2's
    # discriminator, written here so a later reviewer re-runs the test rather
    # than re-deriving it).
    "tx_extra.rs::PqcOwnershipEntry.group_id": Allow(
        "multisig group id — adjacency test (could a path pass a txid, key "
        "image or component hash where a group id belongs?): it is parsed into "
        "a struct and consumed by group logic, and no site takes a bare "
        "[u8; 32] that could be either, so: low. Zero-hash for single-signer. "
        "Reopen when a second consumer appears, or when any site accepts it as "
        "a bare array beside another 32-byte value",
        "shekyl-multisig",
    ),
}

RAW = re.compile(r"\[u8;\s*32\]")
# A `pub` field: `pub name: <ty>` where <ty> mentions [u8; 32].
FIELD_RE = re.compile(r"^\s*pub\s+(?P<name>\w+)\s*:\s*(?P<ty>[^,\n]*\[u8;\s*32\][^,\n]*)")
# A field inside a `pub enum`'s struct variant — public with no `pub`.
VARIANT_FIELD_RE = re.compile(r"^\s+(?P<name>\w+)\s*:\s*(?P<ty>[^,\n]*\[u8;\s*32\][^,\n]*)")
# A tuple variant of a `pub enum`: `Variant([u8; 32])`, `Variant(Vec<[u8; 32]>)`.
# Public with no keyword and no field name — reported as `Enum::Variant.0`.
TUPLE_VARIANT_RE = re.compile(r"^\s{4}(?P<name>[A-Z]\w*)\((?P<ty>[^)]*\[u8;\s*32\][^)]*)\)")
# The start of a `pub fn`. The signature may span lines; the scanner buffers
# from here to the body's `{` (or a trait method's `;`) and checks the whole.
FN_RE = re.compile(r"^\s*pub\s+(?:const\s+|async\s+|unsafe\s+)?fn\s+(?P<name>\w+)")
# `pub struct Name {` / `pub enum Name {` — the enclosing item for a field.
ITEM_RE = re.compile(r"^\s*pub\s+(?P<kind>struct|enum)\s+(?P<name>\w+)")
# An enum variant's struct body: `Variant {`
VARIANT_RE = re.compile(r"^\s{4}(?P<name>[A-Z]\w*)\s*\{")


def signature_ends(line: str) -> bool:
    return "{" in line or line.rstrip().endswith(";")


def scan(root: Path) -> tuple[dict[str, str], int]:
    """Return (occurrence → source text, count of `pub` items seen)."""
    found: dict[str, str] = {}
    pub_items = 0
    for path in sorted(root.rglob("*.rs")):
        rel = str(path.relative_to(root))
        enclosing = "?"
        variant = None
        in_enum = False
        sig: list[str] | None = None  # an open `pub fn` signature being buffered
        sig_name = ""
        for line in path.read_text().splitlines():
            if sig is not None:
                sig.append(line)
                if signature_ends(line):
                    joined = " ".join(part.strip() for part in sig)
                    if RAW.search(joined):
                        found[f"{rel}::{sig_name}()"] = joined
                    sig = None
                continue
            if m := ITEM_RE.match(line):
                enclosing, variant = m.group("name"), None
                in_enum = m.group("kind") == "enum"
                pub_items += 1
                continue
            if m := FN_RE.match(line):
                pub_items += 1
                sig_name = m.group("name")
                if signature_ends(line):
                    if RAW.search(line):
                        found[f"{rel}::{sig_name}()"] = line.strip()
                else:
                    sig = [line]
                continue
            if m := VARIANT_RE.match(line):
                variant = m.group("name")
            if in_enum and (m := TUPLE_VARIANT_RE.match(line)):
                found[f"{rel}::{enclosing}::{m.group('name')}.0"] = line.strip()
                continue
            if not RAW.search(line):
                continue
            if m := FIELD_RE.match(line) or (in_enum and VARIANT_FIELD_RE.match(line)):
                where = f"{enclosing}::{variant}" if variant else enclosing
                found[f"{rel}::{where}.{m.group('name')}"] = line.strip()
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
