#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The archival length's origin, held as a gate until the txid binds it.

# What was ruled, and what is not yet built

`SHT-Q2` (`ARCHIVAL_SHARD_T_DERIVATION.md` §8.6, RULED 2026-09-29) cuts
shards by archival length — the bytes of a transaction's prunable region plus
its `pqc_auths` — and binds that length **through the txid**: the mixer folds
it in, so a pruned form that supplies a wrong length produces a wrong txid and
fails the Merkle check. `PDM-Q6` item 5's principle, which the ruling keeps,
is that no shard boundary may read a value the skeleton cannot bind.

PR #910 built the row (`txs_archival_len`), the cell
(`block_info.cumulative_archival_len`), the boundary function and the prune
over them. It did **not** build the mixer term: `hash_from_components` still
takes the two hashes and no length. Until it does, the invariant holds only
by circumstance — every length the store holds is one `connect` measured on
the segments it had just written, and nothing supplies one from a wire.
That is one new code path away from being false: a pruned P2P receiver, a
skeleton transport or an RPC entry that constructs an `ArchivalLength` from
bytes a peer sent and hands it toward the store would seat an unbound value
under a consensus partition, and the code compiles either way.

# What the gate holds

Two limbs, both read from source (this job has no toolchain):

  * **The mixer is still unbound.** `hash_from_components` in
    `rust/shekyl-wire/src/transaction/txid.rs` carries no archival-length
    operand. When it does, the length is bound and this gate has no subject:
    it then **fails loudly asking to be deleted** (rules 15 and 47 — a gate
    whose subject dissolved must not keep passing), and the cutover PR that
    lands the term removes this file and its workflow step.

  * **While unbound, the length has exactly the origins the ruling names.**
    Every production (non-test) construction of an `ArchivalLength` from a
    raw integer is in one of four places: the type's own home (`SHARD_LENGTH`
    and the partition arithmetic), the wire crate's measurement of the
    segments it serialized, the store codec decoding a row the store wrote,
    and the store's `BlockInfo` decode reading back the cell. The one
    production writer of `txs_archival_len` is `connect.rs`, and what it
    inserts is `segments.archival_len()`. Any other origin, or any other
    writer, is a supplied length and fails.

Rule 47 throughout: each named origin must be found or the allowlist has
drifted and the gate says so; the mixer signature must be found or the gate
cannot ask its question and exits 2. `--selftest` plants each failure on a
synthetic tree — a bound mixer, a stray origin, a second writer, a writer
inserting something other than the measurement, a missing named origin — and
proves the gate sees it, so the negative limb is never a grep that happened
to find nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUST_DIR = REPO / "rust"

MIXER_FILE = "rust/shekyl-wire/src/transaction/txid.rs"
MIXER_FN = "hash_from_components"
WRITER_FILE = "rust/shekyl-chain-store/src/store/connect.rs"
TABLE = "TXS_ARCHIVAL_LEN"

# Production files allowed to construct an `ArchivalLength` from a raw
# integer, and why. Each must be present and must actually construct one, or
# the list has drifted from the tree.
ORIGINS: dict[str, str] = {
    "rust/shekyl-types/src/archival/mod.rs": (
        "the type's home — `SHARD_LENGTH` and the partition arithmetic"
    ),
    "rust/shekyl-wire/src/transaction.rs": (
        "`TxSegments::archival_len` — measured on the bytes just serialized"
    ),
    "rust/shekyl-store-codec/src/vocabulary.rs": (
        "`Canonical for ArchivalLength` — decoding a row the store wrote"
    ),
    "rust/shekyl-chain-store/src/codec/chain.rs": (
        "`BlockInfo` decode — reading back `cumulative_archival_len`"
    ),
}

FROM_RAW = re.compile(r"ArchivalLength::from_raw\s*\(")
# The store-codec impl constructs through `Self::from_raw` inside its own
# `impl Canonical for ArchivalLength`; matched by block, not by line.
CANONICAL_IMPL = re.compile(
    r"impl\s+Canonical\s+for\s+ArchivalLength\s*\{.*?\n\}", re.DOTALL
)
WRITE_CALL = re.compile(r"open_insert_table\s*\(\s*" + TABLE + r"\b")
MEASURED = "let archival_len = segments.archival_len();"
INSERTED = "archival_len.encoded().as_encoded()"
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]", re.MULTILINE)

TEST_PATH_PARTS = ("tests", "harness", "benches", "examples")
TEST_NAME = re.compile(r"(^test_.*\.rs$|_tests?\.rs$|^test_support\.rs$)")


def is_test_file(rel: str) -> bool:
    parts = Path(rel).parts
    if any(p in TEST_PATH_PARTS for p in parts[:-1]):
        return True
    return bool(TEST_NAME.search(parts[-1]))


def production_text(text: str) -> str:
    """The file up to its first `#[cfg(test)]`; unit-test modules sit last."""
    m = CFG_TEST.search(text)
    return text if m is None else text[: m.start()]


def mixer_signature(text: str) -> str | None:
    """The parameter list of `hash_from_components`, or None if absent."""
    m = re.search(r"fn\s+" + MIXER_FN + r"\s*\(", text)
    if m is None:
        return None
    depth, i = 1, m.end()
    while i < len(text) and depth:
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        i += 1
    return text[m.end() : i - 1]


def mixer_bound(signature: str) -> bool:
    return bool(re.search(r"ArchivalLength|archival_len", signature))


def analyse(files: dict[str, str]) -> tuple[bool, list[str]]:
    """(discharged, findings) over a tree given as relative path -> text.

    `discharged` means the mixer now binds the length: the gate's subject is
    gone and it must be deleted. Findings are the while-unbound violations.
    A tree the question cannot be asked of raises SystemExit(2).
    """
    mixer = files.get(MIXER_FILE)
    if mixer is None:
        sys.exit(f"CANNOT ASK: {MIXER_FILE} is missing (rule 47).")
    sig = mixer_signature(production_text(mixer))
    if sig is None:
        sys.exit(f"CANNOT ASK: `fn {MIXER_FN}(` not found in {MIXER_FILE} (rule 47).")
    if mixer_bound(sig):
        return True, []

    findings: list[str] = []

    # Origins: every production construction is in the named set, and every
    # named origin constructs.
    seen: set[str] = set()
    for rel, text in sorted(files.items()):
        if not rel.endswith(".rs") or is_test_file(rel):
            continue
        prod = production_text(text)
        constructs = bool(FROM_RAW.search(prod))
        block = CANONICAL_IMPL.search(prod)
        if block is not None and "from_raw" in block.group(0):
            constructs = True
        if not constructs:
            continue
        if rel in ORIGINS:
            seen.add(rel)
        else:
            lines = [
                i + 1
                for i, line in enumerate(prod.splitlines())
                if FROM_RAW.search(line) or "Self::from_raw" in line
            ]
            findings.append(
                f"{rel}:{','.join(map(str, lines)) or '?'}: constructs an "
                "`ArchivalLength` outside the origins SHT-Q2 names while the "
                "txid does not bind the length — a supplied length. Measure "
                "it from the segments, or land the mixer term first."
            )
    for rel, why in ORIGINS.items():
        if rel not in seen:
            findings.append(
                f"{rel}: named origin ({why}) constructs no `ArchivalLength` — "
                "the allowlist has drifted from the tree (rule 47)."
            )

    # Writers: one, and it inserts the measurement.
    for rel, text in sorted(files.items()):
        if not rel.endswith(".rs") or is_test_file(rel):
            continue
        prod = production_text(text)
        if not WRITE_CALL.search(prod):
            continue
        if rel != WRITER_FILE:
            findings.append(
                f"{rel}: writes `{TABLE}`; the only production writer while "
                f"the length is unbound is {WRITER_FILE}."
            )
    writer = files.get(WRITER_FILE)
    if writer is None:
        sys.exit(f"CANNOT ASK: {WRITER_FILE} is missing (rule 47).")
    wprod = production_text(writer)
    if not WRITE_CALL.search(wprod):
        findings.append(
            f"{WRITER_FILE}: no `open_insert_table({TABLE}` — the writer moved "
            "and the gate no longer reads it (rule 47)."
        )
    elif MEASURED not in wprod or INSERTED not in wprod:
        findings.append(
            f"{WRITER_FILE}: the `{TABLE}` row is not the measured "
            f"`segments.archival_len()` (expected `{MEASURED}` feeding "
            f"`{INSERTED}`)."
        )
    return False, findings


def read_tree() -> dict[str, str]:
    files: dict[str, str] = {}
    for path in RUST_DIR.rglob("*.rs"):
        if "target" in path.parts:
            continue
        rel = path.relative_to(REPO).as_posix()
        files[rel] = path.read_text(encoding="utf-8", errors="replace")
    return files


def report(discharged: bool, findings: list[str]) -> int:
    if discharged:
        print(
            f"FAIL: `{MIXER_FN}` now takes the archival length — the txid binds "
            "it and this gate has no subject. Delete "
            "scripts/ci/check_archival_len_source.py and its step in "
            ".github/workflows/grep-gates.yml in the PR that landed the term "
            "(rules 15, 47), and note it on the FOLLOWUPS \"Build `SHT-Q2`\" row."
        )
        return 1
    if findings:
        print("FAIL: the archival length has an origin SHT-Q2 does not name:")
        for f in findings:
            print(f"  - {f}")
        return 1
    print(
        f"OK: `{MIXER_FN}` is unbound (no length operand) and every production "
        f"`ArchivalLength` is measured or read back — {len(ORIGINS)} named "
        f"origins, one `{TABLE}` writer inserting `segments.archival_len()`."
    )
    return 0


# ----------------------------------------------------------------------------
# Selftest: a synthetic tree, then one planted defect per limb.


def synthetic_tree() -> dict[str, str]:
    mixer = (
        "impl Transaction {\n"
        "    fn hash_from_components(&self, pqc_auth: Option<PqcAuthHash>, "
        "prunable: [u8; 32]) -> TxHash {\n        todo!()\n    }\n}\n"
    )
    origins = {
        "rust/shekyl-types/src/archival/mod.rs": (
            "pub const SHARD_LENGTH: ArchivalLength = "
            "ArchivalLength::from_raw(3_000_000);\n"
            "#[cfg(test)]\nmod tests { fn t() { ArchivalLength::from_raw(1); } }\n"
        ),
        "rust/shekyl-wire/src/transaction.rs": (
            "pub fn archival_len(&self) -> ArchivalLength {\n"
            "    ArchivalLength::from_raw(bytes)\n}\n"
        ),
        "rust/shekyl-store-codec/src/vocabulary.rs": (
            "impl Canonical for ArchivalLength {\n"
            "    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {\n"
            "        u64::decode(bytes).map(Self::from_raw)\n    }\n}\n"
        ),
        "rust/shekyl-chain-store/src/codec/chain.rs": (
            "cumulative_archival_len: ArchivalLength::from_raw(le_u64(&b[104..112])),\n"
        ),
    }
    writer = (
        "        let archival_len = segments.archival_len();\n"
        "        if archival_len > ArchivalLength::ZERO {\n"
        "            self.open_insert_table(TXS_ARCHIVAL_LEN, "
        "StoreInvariant::IdNotFresh)?\n"
        "                .insert(tx_id.to_raw(), "
        "archival_len.encoded().as_encoded())?;\n        }\n"
    )
    tree = {MIXER_FILE: mixer, WRITER_FILE: writer, **origins}
    tree["rust/shekyl-chain-store/src/store/prune_tests.rs"] = (
        "let x = ArchivalLength::from_raw(99_999);\n"
    )
    tree["rust/shekyl-chain-rules/src/harness/fixture/mod.rs"] = (
        "cumulative_archival_len: ArchivalLength::from_raw(0),\n"
    )
    return tree


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, tree: dict[str, str], *, discharged: bool, hits: int) -> None:
        got_d, got_f = analyse(tree)
        if got_d != discharged or (hits and not got_f) or (not hits and got_f):
            failures.append(
                f"{name}: expected discharged={discharged} findings={'>0' if hits else '0'}, "
                f"got discharged={got_d} findings={got_f}"
            )

    clean = synthetic_tree()
    expect("clean tree passes (test files ignored)", clean, discharged=False, hits=0)

    bound = dict(clean)
    bound[MIXER_FILE] = clean[MIXER_FILE].replace(
        "prunable: [u8; 32])", "prunable: [u8; 32], archival_len: ArchivalLength)"
    )
    expect("bound mixer is discharged", bound, discharged=True, hits=0)

    stray = dict(clean)
    stray["rust/shekyl-levin/src/payload/block.rs"] = (
        "let len = ArchivalLength::from_raw(read_u64(buf)?);\n"
    )
    expect("stray production origin fails", stray, discharged=False, hits=1)

    second = dict(clean)
    second["rust/shekyl-chain-store/src/store/ingest.rs"] = (
        "self.open_insert_table(TXS_ARCHIVAL_LEN, StoreInvariant::IdNotFresh)?"
        ".insert(id, len.encoded().as_encoded())?;\n"
    )
    expect("second writer fails", second, discharged=False, hits=1)

    unmeasured = dict(clean)
    unmeasured[WRITER_FILE] = clean[WRITER_FILE].replace(
        MEASURED, "let archival_len = supplied_len;"
    )
    expect("writer not inserting the measurement fails", unmeasured, discharged=False, hits=1)

    drifted = dict(clean)
    drifted["rust/shekyl-wire/src/transaction.rs"] = "pub fn archival_len() {}\n"
    expect("named origin that no longer constructs fails", drifted, discharged=False, hits=1)

    multiline = dict(clean)
    multiline[MIXER_FILE] = (
        "fn hash_from_components(\n    &self,\n    pqc_auth: Option<PqcAuthHash>,\n"
        "    prunable: [u8; 32],\n) -> TxHash { todo!() }\n"
    )
    expect("multi-line unbound signature still read", multiline, discharged=False, hits=0)

    if failures:
        print("SELFTEST FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SELFTEST OK: 7 synthetic cases, each limb seen to go red and green.")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    if argv[1:]:
        sys.exit(f"usage: {argv[0]} [--selftest]")
    discharged, findings = analyse(read_tree())
    return report(discharged, findings)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
