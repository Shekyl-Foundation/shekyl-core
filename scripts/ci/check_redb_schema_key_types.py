# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-0 slice B: a redb key/value type must reproduce its LMDB table's ORDERING.
#
# The bijection gate beside this one checks that every table is MAPPED. It
# cannot check that a mapping is CORRECT, and that gap was not theoretical:
# review of the first landing found three `MDB_INTEGERKEY` tables mapped as
# `&[u8]` and one DUPSORT multimap whose values ignored `compare_uint64`.
# Names were 49/49 while four orderings were wrong. This gate closes that
# axis.
#
# WHY ORDERING AND NOT BYTES. redb need not store what LMDB stored — the store
# is new and reads no LMDB file. What it must reproduce is the ORDER, because
# range scans and ordered iteration are consensus-visible where a reader
# consumes sequence rather than a set.
#
# THE RULES, each derived from `db_lmdb.cpp` and each unambiguous. No
# hardcoded table-name set: INTEGERKEY+DUPSORT+compare_hash32 *is* the
# zerokval-collapse-to-hash-key signal (those three tables, and no other),
# and every other INTEGERKEY table — including zerokval collapse to a
# numeric key — is `u64`.
#
#   mdb_set_compare compare_hash32     -> LmdbHashKey
#   mdb_set_compare compare_string     -> &str
#   mdb_set_dupsort compare_hash32     -> LmdbHashKey  (zerokval collapse)
#   MDB_INTEGERKEY                     -> u64
#   multimap + dupsort compare_uint64  -> value U64PrefixBytes
#
# DEFAULT-FLAG TABLES ARE DELIBERATELY UNCONSTRAINED. Several store `BE(x)`
# 8-byte integer keys under LMDB's default byte comparator, and big-endian
# bytes compared lexicographically ARE numeric order — so `u64` (which redb
# orders numerically) preserves it, and so does `&[u8]`. Both are correct;
# a rule here would fail correct code, which teaches people to weaken gates.
#
# Instance of 47-gate-subject-assertion.mdc: zero parsed definitions, zero
# parsed tables, or a missed `lmdb_db_open` (which would look like a
# default-flag table) fail loudly. `--selftest` pins the rule function,
# including the two zerokval-uint64 tables a name-set elif used to swallow.

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LMDB = ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp"
SCHEMA = ROOT / "rust/shekyl-chain-store/src/schema.rs"

# Floor: 30 constraints were live when this gate's INTEGERKEY fall-through
# started covering the two zerokval-uint64 tables. A parse that yields fewer
# is a broken extractor, not a smaller schema.
MIN_CONSTRAINTS = 30

DEF_RE = re.compile(
    r"pub const \w+:\s*(Multimap)?TableDefinition<\s*([^,]+?)\s*,\s*([^>]+?)\s*>\s*=\s*"
    r"(?:Multimap)?TableDefinition::new\(\"([^\"]+)\"\)",
    re.S,
)


def expected_key_type(flags: str, kinds: dict[str, str]) -> str | None:
    """Return the required redb key type, or None if the table is unconstrained."""
    if kinds.get("compare") == "compare_hash32":
        return "LmdbHashKey"
    if kinds.get("compare") == "compare_string":
        return "&str"
    if kinds.get("dupsort") == "compare_hash32":
        return "LmdbHashKey"
    if "MDB_INTEGERKEY" in flags:
        return "u64"
    return None


def expected_multimap_value(is_multimap: bool, kinds: dict[str, str]) -> str | None:
    if is_multimap and kinds.get("dupsort") == "compare_uint64":
        return "U64PrefixBytes"
    return None


def lmdb_facts():
    src = LMDB.read_text(encoding="utf-8")
    macro = re.search(r"#define SHEKYL_LMDB_TABLES\(X\)(.*?)\n\n", src, re.S)
    if not macro:
        return None, None, None
    names = re.findall(r'X\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)', macro.group(1))
    opens = {
        m.group(1): (m.group(2).strip(), m.group(3))
        for m in re.finditer(r"lmdb_db_open\(txn,\s*(\w+)\s*,\s*([^,]+),\s*(\w+),", src)
    }
    cmps = {}
    for m in re.finditer(r"mdb_set_(dupsort|compare)\(txn,\s*m_(\w+),\s*(\w+)\)", src):
        cmps.setdefault(m.group(2), []).append((m.group(1), m.group(3)))
    facts = {}
    for const, name in names:
        flags, member = opens.get(const, ("", ""))
        facts[name] = (flags, cmps.get(re.sub(r"^m_", "", member), []), const)
    return facts, names, opens


def selftest() -> None:
    # Real tables, stripped to (flags, kinds). A regression that reintroduces
    # a name-set elif swallowing INTEGERKEY is this function going red.
    cases = [
        (
            "spent_keys collapse",
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_hash32"},
            "LmdbHashKey",
        ),
        (
            "block_info collapse",
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_uint64"},
            "u64",
        ),
        (
            "output_txs collapse",
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_uint64"},
            "u64",
        ),
        (
            "output_to_leaf INTEGERKEY",
            "MDB_INTEGERKEY | MDB_CREATE",
            {},
            "u64",
        ),
        (
            "txpool_meta hash key",
            "MDB_CREATE",
            {"compare": "compare_hash32"},
            "LmdbHashKey",
        ),
        (
            "properties string key",
            "MDB_CREATE",
            {"compare": "compare_string"},
            "&str",
        ),
        (
            "default-flag BE key unconstrained",
            "MDB_CREATE",
            {},
            None,
        ),
    ]
    failures = []
    for label, flags, kinds, want in cases:
        got = expected_key_type(flags, kinds)
        if got != want:
            failures.append(f"{label}: expected key {want!r}, got {got!r}")
    got_val = expected_multimap_value(True, {"dupsort": "compare_uint64"})
    if got_val != "U64PrefixBytes":
        failures.append(
            f"output_amounts value: expected 'U64PrefixBytes', got {got_val!r}"
        )
    if expected_multimap_value(False, {"dupsort": "compare_uint64"}) is not None:
        failures.append("non-multimap uint64 dupsort must not constrain the value type")
    if failures:
        print("redb key-type selftest FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)
    print(f"redb key-type selftest: {len(cases)} key-rule cases + 2 value-rule cases, all held")


def main():
    failures = []
    for p in (LMDB, SCHEMA):
        if not p.is_file():
            failures.append(f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist")
    if failures:
        report(failures)

    facts, names, opens = lmdb_facts()
    if not facts:
        report([f"{LMDB.name}: SHEKYL_LMDB_TABLES did not parse — subject missing"])

    missing_opens = [c for c, _ in names if c not in opens]
    if missing_opens:
        report(
            [
                f"{LMDB.name}: lmdb_db_open parse missed {len(missing_opens)} X-macro "
                f"const(s): {', '.join(missing_opens)} — a missed open looks like a "
                "default-flag table, which this gate deliberately does not constrain"
            ]
        )
    if len(opens) != len(names):
        extra = sorted(set(opens) - {c for c, _ in names})
        report(
            [
                f"{LMDB.name}: parsed {len(opens)} lmdb_db_open calls against "
                f"{len(names)} X-macro consts"
                + (f"; extras: {', '.join(extra)}" if extra else "")
            ]
        )

    schema = SCHEMA.read_text(encoding="utf-8")
    defs = DEF_RE.findall(schema)
    if not defs:
        report([f"{SCHEMA.name}: parsed ZERO table definitions — subject missing"])
    if not names:
        report([f"{LMDB.name}: parsed ZERO tables — subject missing"])

    checked = 0
    for multimap, key, value, name in defs:
        if name not in facts:
            failures.append(
                f"{name}: TableDefinition has no matching X-macro/open facts"
            )
            continue
        flags, cmps, _const = facts[name]
        key, value = key.strip(), value.strip()
        kinds = {k: fn for k, fn in cmps}

        def want(expected, got, what):
            nonlocal checked
            checked += 1
            if got != expected:
                failures.append(
                    f"{name}: {what} is `{got}`, must be `{expected}` — LMDB flags "
                    f"`{flags.strip()}` / comparators {cmps or 'none'}"
                )

        exp_key = expected_key_type(flags, kinds)
        if exp_key is not None:
            want(exp_key, key, "key type")
        exp_val = expected_multimap_value(bool(multimap), kinds)
        if exp_val is not None:
            want(exp_val, value, "multimap value type")

    if checked == 0:
        failures.append(
            "no rule matched any table — the fact extraction or the definition "
            "parse is broken, and zero checks pass vacuously"
        )
    elif checked < MIN_CONSTRAINTS:
        failures.append(
            f"only {checked} ordering constraints fired (floor {MIN_CONSTRAINTS}) — "
            "broken extractor or a mass rule deletion; both need a human"
        )

    report(failures)
    print(
        f"redb key-type ordering: {len(defs)} definitions parsed, {checked} ordering "
        f"constraints checked against db_lmdb.cpp, all satisfied"
    )


def report(failures):
    if failures:
        print("redb key-type ordering FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()
