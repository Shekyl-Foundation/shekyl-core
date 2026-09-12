# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-0 slice B: a redb key/value type must reproduce its LMDB table's ORDERING.
#
# The bijection gate beside this one checks that every table is MAPPED. It
# explicitly cannot check that a mapping is CORRECT, and that gap was not
# theoretical: review of the first landing found three `MDB_INTEGERKEY` tables
# mapped as `&[u8]` (`output_to_leaf`, `leaf_to_output`, `curve_tree_layers`)
# and one DUPSORT multimap whose values ignored `compare_uint64`. Names were
# 49/49 while four orderings were wrong. This gate closes that axis.
#
# WHY ORDERING AND NOT BYTES. redb need not store what LMDB stored — the store
# is new and reads no LMDB file. What it must reproduce is the ORDER, because
# range scans and ordered iteration are consensus-visible where a reader
# consumes sequence rather than a set.
#
# THE RULES, each derived from `db_lmdb.cpp` and each unambiguous:
#
#   MDB_INTEGERKEY (not zerokval)   -> u64        LMDB orders numerically;
#                                                 byte-lex over little-endian
#                                                 bytes does not.
#   mdb_set_compare compare_hash32  -> LmdbHashKey  reversed-byte order.
#   mdb_set_compare compare_string  -> &str       byte-lex + length tiebreak.
#   zerokval + dupsort hash32       -> LmdbHashKey  the dup value becomes the key.
#   multimap + dupsort compare_uint64 -> value U64PrefixBytes
#                                                 dups order by a native u64
#                                                 prefix, not whole-value bytes.
#
# DEFAULT-FLAG TABLES ARE DELIBERATELY UNCONSTRAINED. Several store `BE(x)`
# 8-byte integer keys under LMDB's default byte comparator, and big-endian
# bytes compared lexicographically ARE numeric order — so `u64` (which redb
# orders numerically) preserves it, and so does `&[u8]`. Both are correct;
# a rule here would fail correct code, which teaches people to weaken gates.
#
# Instance of 47-gate-subject-assertion.mdc: zero parsed definitions or zero
# parsed tables would satisfy every rule vacuously.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LMDB = ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp"
SCHEMA = ROOT / "rust/shekyl-chain-store/src/schema.rs"

# Tables using LMDB's dummy-key ("zerokval") pattern: the real identifier lives
# in the fixed-size duplicate value, so under redb it becomes the key.
ZEROKVAL = {"block_heights", "block_info", "output_txs", "spent_keys", "tx_indices"}

DEF_RE = re.compile(
    r"pub const \w+:\s*(Multimap)?TableDefinition<\s*([^,]+?)\s*,\s*([^>]+?)\s*>\s*=\s*"
    r"(?:Multimap)?TableDefinition::new\(\"([^\"]+)\"\)",
    re.S,
)


def lmdb_facts():
    src = LMDB.read_text(encoding="utf-8")
    macro = re.search(r"#define SHEKYL_LMDB_TABLES\(X\)(.*?)\n\n", src, re.S)
    if not macro:
        return None, None, None
    names = re.findall(r'X\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)', macro.group(1))
    opens = {
        m.group(1): (m.group(2).strip(), m.group(3))
        for m in re.finditer(r"lmdb_db_open\(txn,\s*(\w+),\s*([^,]+),\s*(\w+),", src)
    }
    cmps = {}
    for m in re.finditer(r"mdb_set_(dupsort|compare)\(txn,\s*m_(\w+),\s*(\w+)\)", src):
        cmps.setdefault(m.group(2), []).append((m.group(1), m.group(3)))
    facts = {}
    for const, name in names:
        flags, member = opens.get(const, ("", ""))
        facts[name] = (flags, cmps.get(re.sub(r"^m_", "", member), []))
    return facts, names, opens


def main():
    failures = []
    for p in (LMDB, SCHEMA):
        if not p.is_file():
            failures.append(f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist")
    if failures:
        report(failures)

    facts, names, _ = lmdb_facts()
    if not facts:
        report([f"{LMDB.name}: SHEKYL_LMDB_TABLES did not parse — subject missing"])

    schema = SCHEMA.read_text(encoding="utf-8")
    defs = DEF_RE.findall(schema)
    if not defs:
        report([f"{SCHEMA.name}: parsed ZERO table definitions — subject missing"])
    if not names:
        report([f"{LMDB.name}: parsed ZERO tables — subject missing"])

    checked = 0
    for multimap, key, value, name in defs:
        flags, cmps = facts.get(name, ("", []))
        key, value = key.strip(), value.strip()
        kinds = {k: fn for k, fn in cmps}

        def want(expected, got, what):
            nonlocal checked
            checked += 1
            if got != expected:
                failures.append(
                    f"{name}: {what} is `{got}`, must be `{expected}` — LMDB flags "
                    f"`{flags.strip()}` / comparators {cmps or 'none'}")

        if kinds.get("compare") == "compare_hash32":
            want("LmdbHashKey", key, "key type")
        elif kinds.get("compare") == "compare_string":
            want("&str", key, "key type")
        elif name in ZEROKVAL:
            if kinds.get("dupsort") == "compare_hash32":
                want("LmdbHashKey", key, "key type (zerokval collapse)")
        elif "MDB_INTEGERKEY" in flags:
            want("u64", key, "key type")

        if multimap and kinds.get("dupsort") == "compare_uint64":
            want("U64PrefixBytes", value, "multimap value type")

    if checked == 0:
        failures.append(
            "no rule matched any table — the fact extraction or the definition "
            "parse is broken, and zero checks pass vacuously")

    report(failures)
    print(f"redb key-type ordering: {len(defs)} definitions parsed, {checked} ordering "
          f"constraints checked against db_lmdb.cpp, all satisfied")


def report(failures):
    if failures:
        print("redb key-type ordering FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
