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
#   MDB_INTEGERKEY                     -> u64, or the tuple that UNPACKS a
#                                         composite key: where the C++ builds
#                                         the table's key with a shift-or pack
#                                         `(uintA_t hi << (64 - A)) | lo`
#                                         (`ct_layer_chunk_key`, S-CURVE), the
#                                         tuple `(uA, u64)` orders component-
#                                         wise exactly as the packed u64 does
#                                         over every key the pack can produce
#                                         — the high field is the high bits —
#                                         so both reproduce LMDB's order. The
#                                         pack is read off the builder's body
#                                         and bound to the table its callers
#                                         address (`packed_key_facts`); a
#                                         shift that is not `64 - A` is not
#                                         order-equivalent and mints no tuple.
#                                         `SCU-Q3` ruled the tuple for
#                                         `curve_tree_layers`.
#   MDB_INTEGERKEY + dupsort compare_uint64: decided by HOW THE C++ WRITES
#                                         the table — the key argument of its
#                                         `mdb_cursor_put` calls, which is the
#                                         fact the flags do not carry:
#     every put keyed by `zerokval`      -> u64            (a collapse: the dup
#                                         IS the key; block_info, output_txs)
#     a real key, put with MDB_APPENDDUP -> (u64, u64)     (a genuine multi-
#                                         member DUPSORT: (key, dup) as a
#                                         tuple, whose lexicographic order over
#                                         two numeric u64s is INTEGERKEY then
#                                         compare_uint64; S-OUT-KI SOK-1,
#                                         `output_amounts`)
#     a real key, put without APPENDDUP  -> u64 or (u64, u64) (the key's order
#                                         is what is consensus-visible; whether
#                                         the dup is a second key component or
#                                         part of the value is a shape choice
#                                         both of which preserve it)
#   A uint64-dupsort INTEGERKEY table with NO parsed put is a gate failure,
#   not an unconstrained table: the fact that classifies it is missing.
#
# No multimap rule remains: the catalogue has no multimap since S-OUT-KI's
# layout commit. A future multimap re-mints its rule here with its table.
#
# DEFAULT-FLAG TABLES ARE DELIBERATELY UNCONSTRAINED. Several store `BE(x)`
# 8-byte integer keys under LMDB's default byte comparator, and big-endian
# bytes compared lexicographically ARE numeric order — so `u64` (which redb
# orders numerically) preserves it, and so does `&[u8]`. Both are correct;
# a rule here would fail correct code, which teaches people to weaken gates.
#
# Instance of 47-gate-subject-assertion.mdc: zero parsed definitions, zero
# parsed tables, a missed `lmdb_db_open` (which would look like a
# default-flag table), or a uint64-dupsort table with no parsed put (which
# would look like an unconstrained one) fail loudly. `--selftest` pins the
# rule function, including the two zerokval-uint64 tables a name-set elif
# used to swallow and the three put-shapes that tell a collapse from a
# genuine DUPSORT (PR #783 review: accepting both shapes for every
# uint64-dupsort table let `output_amounts` lose its amount component, or
# `block_info` gain a spurious one, without the gate noticing).

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_redb_schema_bijection import parse_rust_only  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
LMDB = ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp"
SCHEMA = ROOT / "rust/shekyl-chain-store/src/schema.rs"

# Floor: 30 constraints were live when this gate's INTEGERKEY fall-through
# started covering the two zerokval-uint64 tables; 29 since S-OUT-KI's layout
# commit retired the one multimap value rule (`output_amounts` now fires one
# key constraint, the tuple, where it fired a key and a member rule). A parse
# that yields fewer is a broken extractor, not a smaller schema — the floor
# moves only with a rule, never to make a run pass. 27 since LMDB v15 / redb
# v10 dropped two INTEGERKEY tables (`txs_prunable_tip`, `output_metadata`)
# with the C++ tx-data prune: two key constraints fewer because two tables
# fewer, re-derived by counting, not by subtracting. 25 since redb v12
# (DRS-E1 S-POOL): `txpool_meta` and `txpool_blob` left `schema.rs` for the
# pool file (`MIRRORED_ELSEWHERE`), and this gate iterates definitions in
# `schema.rs` — the two `compare_hash32` constraints they fired go with them.
# The pool file's keys are not LMDB's order and are outside this gate's
# domain by construction; the bijection gate holds the twins' existence.
MIN_CONSTRAINTS = 25

# Tables the C++ no longer writes at all, with the put shape they carried
# when they were last written. The classifying fact for a uint64-dupsort
# INTEGERKEY table is its put; a table with no put has no fact, and this
# gate treats a missing fact as red rather than as "unconstrained" — so a
# table that legitimately lost its writer needs its last shape declared here,
# by name, with the reason. Each entry is a reversion clause (rule 21): the
# gate goes red if the table gains a put again (the entry must go) or leaves
# the X-macro (the entry is stale), so the declaration cannot outlive either
# of the facts it stands in for.
WRITE_NEVER: dict[str, tuple[str, str]] = {
    # (empty since LMDB v15 dropped `txs_prunable_tip`, the entry that
    # motivated this map — it expired the way the mechanism says: the table
    # left the X-macro and the gate went red until the entry followed.)
}

# The value type may itself be generic — `Coded<BlockInfo>`, `Blob<BlockBody>`
# (DAEMON_REDB_STORE.md §11.1(f)) — so it is matched up to the `=` rather than
# to the first `>`. Keys are not generic but may be a **tuple** (`(u64, u64)`,
# `output_amounts`), whose inner comma the old `[^,]` group could not cross —
# it dropped the definition silently and only the constraint floor noticed
# (the undercounting failure mode this file's header names). A tuple is
# matched as a parenthesised group.
DEF_RE = re.compile(
    r"pub const \w+:\s*(Multimap)?TableDefinition<\s*(\([^)]*\)|[^,]+?)\s*,\s*(.+?)\s*>\s*=\s*"
    r"(?:Multimap)?TableDefinition::new\(\"([^\"]+)\"\)",
    re.S,
)


# How the C++ writes a table, read off its `mdb_cursor_put` calls. This is the
# fact that separates a zerokval collapse from a genuine DUPSORT table: the
# open flags of `block_info` and `output_amounts` are identical.
PUT_ZEROKVAL = "zerokval"  # every put keyed by the dummy key: the dup is the key
PUT_REAL_APPENDDUP = "real+appenddup"  # real key, members appended in dup order
PUT_REAL = "real"  # real key, no APPENDDUP: one member per key in practice
PUT_UNSEEN = None  # no put parsed — the classifying fact is missing


class UnclassifiedTable(Exception):
    """A uint64-dupsort INTEGERKEY table whose put shape did not parse. Raised,
    not returned as None, so a missing fact reads as a gate failure rather
    than as an unconstrained table."""


def expected_key_types(
    flags: str,
    kinds: dict[str, str],
    put: str | None = PUT_UNSEEN,
    packed: tuple[int, int] | None = None,
) -> tuple[str, ...] | None:
    """The redb key types that reproduce the table's LMDB order, or None if
    the table is unconstrained. More than one only where two shapes both
    preserve the order LMDB's facts pin (a real-keyed DUPSORT table written
    without APPENDDUP), never where the facts pick one."""
    if kinds.get("compare") == "compare_hash32":
        return ("LmdbHashKey",)
    if kinds.get("compare") == "compare_string":
        return ("&str",)
    if kinds.get("dupsort") == "compare_hash32":
        return ("LmdbHashKey",)
    if "MDB_INTEGERKEY" in flags:
        if kinds.get("dupsort") != "compare_uint64":
            if packed is not None:
                hi_bits, shift = packed
                if shift == 64 - hi_bits:
                    return ("u64", f"(u{hi_bits}, u64)")
            return ("u64",)
        if put == PUT_ZEROKVAL:
            return ("u64",)
        if put == PUT_REAL_APPENDDUP:
            return ("(u64, u64)",)
        if put == PUT_REAL:
            return ("u64", "(u64, u64)")
        raise UnclassifiedTable(
            "INTEGERKEY + dupsort compare_uint64, but no `mdb_cursor_put` on the "
            "table's cursor parsed — a collapse and a genuine DUPSORT cannot be told apart"
        )
    return None


def classify_puts(puts: list[tuple[str, str]]) -> str | None:
    """Fold a table's `(key argument, flags)` put pairs into one put shape.

    An `MDB_CURRENT` put overwrites the record the cursor already sits on;
    its key argument is not how the table is keyed (`block_info`'s in-place
    update positions with `zerokval` and then puts with `&key2`), so it says
    nothing here and is left out of the fold."""
    inserts = [(key, fl) for key, fl in puts if "MDB_CURRENT" not in fl]
    if not inserts:
        return PUT_UNSEEN
    if all("zerokval" in key for key, _ in inserts):
        return PUT_ZEROKVAL
    if any("MDB_APPENDDUP" in fl for _, fl in inserts):
        return PUT_REAL_APPENDDUP
    return PUT_REAL


# A composite key built by shift-or: `uint64_t f(uintA_t hi, uint64_t lo) {
# return (static_cast<uint64_t>(hi) << S) | lo; }`. Captures (name, A, S).
PACK_RE = re.compile(
    r"uint64_t\s+(\w+)\s*\(\s*uint(\d+)_t\s+(\w+)\s*,\s*uint64_t\s+\w+\s*\)\s*\{\s*"
    r"return\s*\(\s*static_cast<uint64_t>\(\s*\3\s*\)\s*<<\s*(\d+)\s*\)\s*\|\s*\w+\s*;",
    re.S,
)
# How far below a pack call the table it keys is addressed. Every site in
# db_lmdb.cpp is `key = f(..); MDB_val k = {..}; mdb_*(txn, m_<table>, &k, ..)`,
# three lines; the window is generous, not loose — a second table inside it
# is ambiguity, and ambiguity is a raise, not a guess.
PACK_WINDOW_LINES = 8


class AmbiguousPack(Exception):
    """A packed-key builder whose call sites address more than one table, or
    none: the fact that binds the pack to a table is missing."""


def packed_key_facts(src: str) -> dict[str, tuple[int, int]]:
    """`{table member: (hi_bits, shift)}` for every shift-or key builder in
    `src`, bound to the table its callers address within `PACK_WINDOW_LINES`
    of the call. Raises `AmbiguousPack` rather than guessing."""
    lines = src.splitlines()
    out: dict[str, tuple[int, int]] = {}
    for m in PACK_RE.finditer(src):
        fn, hi_bits, _hi, shift = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        tables: set[str] = set()
        call = re.compile(r"=\s*" + re.escape(fn) + r"\s*\(")
        for i, line in enumerate(lines):
            if not call.search(line):
                continue
            window = "\n".join(lines[i : i + PACK_WINDOW_LINES])
            # The dbi is the argument after the txn (`mdb_get(txn, m_<t>, ..)`);
            # a cursor op names its table in the cursor (`m_cur_<t>`).
            tables.update(re.findall(r"mdb_(?:get|put|del)\(\s*[^,]+,\s*m_(\w+)\b", window))
            tables.update(re.findall(r"mdb_cursor_\w+\(\s*m_cur_(\w+)\b", window))
        if len(tables) != 1:
            raise AmbiguousPack(
                f"{fn}: pack builder's call sites address {sorted(tables) or 'no'} table(s); "
                "exactly one is the fact that binds a pack to a table"
            )
        out[tables.pop()] = (hi_bits, shift)
    return out


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
    # Every `mdb_cursor_put(m_cur_<member>, <key>, <data>, <flags>)`, by member;
    # the key argument and the flags are the put shape (`classify_puts`).
    puts = {}
    for m in re.finditer(
        r"mdb_cursor_put\(\s*m_cur_(\w+)\s*,\s*([^,]+),\s*[^,]+,\s*([^)]*)\)", src
    ):
        puts.setdefault(m.group(1), []).append((m.group(2).strip(), m.group(3).strip()))
    packs = packed_key_facts(src)
    facts = {}
    for const, name in names:
        flags, member = opens.get(const, ("", ""))
        member = re.sub(r"^m_", "", member)
        facts[name] = (
            flags,
            cmps.get(member, []),
            const,
            classify_puts(puts.get(member, [])),
            packs.get(member),
        )
    return facts, names, opens


def selftest() -> None:
    # Real tables, stripped to (flags, kinds). A regression that reintroduces
    # a name-set elif swallowing INTEGERKEY is this function going red.
    cases = [
        (
            "spent_keys collapse",
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_hash32"},
            PUT_ZEROKVAL,
            ("LmdbHashKey",),
        ),
        (
            "block_info collapse: puts keyed by zerokval, exactly u64",
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_uint64"},
            PUT_ZEROKVAL,
            ("u64",),
        ),
        (
            "output_amounts genuine DUPSORT: real key + APPENDDUP, exactly the tuple",
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_uint64"},
            PUT_REAL_APPENDDUP,
            ("(u64, u64)",),
        ),
        (
            "txs_prunable_hash: real key without APPENDDUP, either shape",
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_uint64"},
            PUT_REAL,
            ("u64", "(u64, u64)"),
        ),
        (
            "output_to_leaf INTEGERKEY",
            "MDB_INTEGERKEY | MDB_CREATE",
            {},
            PUT_UNSEEN,
            ("u64",),
        ),
        (
            "txpool_meta hash key",
            "MDB_CREATE",
            {"compare": "compare_hash32"},
            PUT_UNSEEN,
            ("LmdbHashKey",),
        ),
        (
            "properties string key",
            "MDB_CREATE",
            {"compare": "compare_string"},
            PUT_UNSEEN,
            ("&str",),
        ),
        (
            "default-flag BE key unconstrained",
            "MDB_CREATE",
            {},
            PUT_UNSEEN,
            None,
        ),
    ]
    failures = []
    for label, flags, kinds, put, want in cases:
        got = expected_key_types(flags, kinds, put)
        if got != want:
            failures.append(f"{label}: expected key {want!r}, got {got!r}")
    # A packed INTEGERKEY admits the order-equivalent tuple, and only that
    # one: the high field must be the high bits (`shift == 64 - A`).
    packed_cases = [
        ("curve_tree_layers pack (8, 56)", (8, 56), ("u64", "(u8, u64)")),
        ("a pack whose shift is not 64 - A is not order-equivalent", (8, 40), ("u64",)),
        ("a 16-bit high field", (16, 48), ("u64", "(u16, u64)")),
    ]
    for label, packed, want in packed_cases:
        got = expected_key_types("MDB_INTEGERKEY | MDB_CREATE", {}, PUT_UNSEEN, packed)
        if got != want:
            failures.append(f"{label}: expected key {want!r}, got {got!r}")
    # The pack extractor: the builder's body, and the binding to the table
    # its callers address — one table, or a raise.
    pack_src = """
  uint64_t ct_layer_chunk_key(uint8_t layer, uint64_t chunk) {
    return (static_cast<uint64_t>(layer) << 56) | chunk;
  }
  void f() {
    uint64_t layer_key = ct_layer_chunk_key(layer, chunk);
    MDB_val k = {sizeof(layer_key), (void *)&layer_key};
    const int result = mdb_del(*m_write_txn, m_curve_tree_layers, &k, nullptr);
  }
"""
    if packed_key_facts(pack_src) != {"curve_tree_layers": (8, 56)}:
        failures.append(f"pack extractor: {packed_key_facts(pack_src)!r}")
    try:
        packed_key_facts(pack_src.replace("mdb_del(*m_write_txn, m_curve_tree_layers", "g("))
        failures.append("a pack bound to no table was accepted instead of raised")
    except AmbiguousPack:
        pass
    if packed_key_facts("  uint64_t plain(uint64_t a) { return a; }\n") != {}:
        failures.append("a non-pack builder minted a pack fact")
    # A uint64-dupsort table with no parsed put is a failure, never None.
    try:
        expected_key_types(
            "MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED",
            {"dupsort": "compare_uint64"},
            PUT_UNSEEN,
        )
        failures.append("unclassified uint64-dupsort table was accepted instead of raised")
    except UnclassifiedTable:
        pass
    # The put-shape fold, on the three shapes db_lmdb.cpp actually writes.
    folds = [
        ("zerokval puts", [("(MDB_val *)&zerokval", "MDB_APPENDDUP")], PUT_ZEROKVAL),
        ("real key + APPENDDUP", [("&val_amount", "MDB_APPENDDUP")], PUT_REAL_APPENDDUP),
        ("real key + APPEND", [("&val_tx_id", "MDB_APPEND")], PUT_REAL),
        (
            "block_info: zerokval insert plus an in-place MDB_CURRENT update",
            [("(MDB_val *)&zerokval", "MDB_APPENDDUP"), ("&key2", "MDB_CURRENT")],
            PUT_ZEROKVAL,
        ),
        ("no puts", [], PUT_UNSEEN),
        ("only an MDB_CURRENT update", [("&key2", "MDB_CURRENT")], PUT_UNSEEN),
    ]
    for label, puts, want in folds:
        got = classify_puts(puts)
        if got != want:
            failures.append(f"put fold {label}: expected {want!r}, got {got!r}")
    # WRITE_NEVER: a declared shape must be a shape the rule function accepts
    # (a typo here would silently classify nothing), and the declared table
    # must be one the X-macro parse can find on this tree.
    for wn_name, (wn_shape, _why) in WRITE_NEVER.items():
        if wn_shape not in (PUT_ZEROKVAL, PUT_REAL_APPENDDUP, PUT_REAL):
            failures.append(f"WRITE_NEVER[{wn_name!r}] declares unknown put shape {wn_shape!r}")
        if wn_name not in (lmdb_facts()[0] or {}):
            failures.append(f"WRITE_NEVER[{wn_name!r}] names a table the X-macro parse does not find")
    # The tuple parse: the key group must cross the inner comma.
    m = DEF_RE.search(
        'pub const X: TableDefinition<(u64, u64), Coded<OutKey>> = TableDefinition::new("x");'
    )
    if not m or m.group(2) != "(u64, u64)" or m.group(3) != "Coded<OutKey>":
        failures.append(f"tuple-key definition did not parse: {m and m.groups()!r}")
    if failures:
        print("redb key-type selftest FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)
    print(
        f"redb key-type selftest: {len(cases)} key-rule cases + 1 unclassified case + "
        f"{len(packed_cases)} packed-key cases + 3 pack-extractor cases + "
        f"{len(folds)} put-fold cases + 1 parse case, all held"
    )


def main():
    failures = []
    for p in (LMDB, SCHEMA):
        if not p.is_file():
            failures.append(f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist")
    if failures:
        report(failures)

    try:
        facts, names, opens = lmdb_facts()
    except AmbiguousPack as e:
        report([f"{LMDB.name}: {e}"])
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

    # A WRITE_NEVER entry names a table that must still exist in the X-macro:
    # once a layout bump drops the table, the entry is a declaration about
    # nothing and has to go with it.
    for stale in sorted(set(WRITE_NEVER) - set(facts)):
        failures.append(
            f"{stale}: named in WRITE_NEVER ({WRITE_NEVER[stale][1]}) but no longer in the "
            f"X-macro — the table is gone; remove the WRITE_NEVER entry"
        )

    # Rust-only tables (schema.rs `RUST_ONLY_TABLES`) have no LMDB flags to
    # derive a key type from, so they are outside this gate's domain — but
    # only when named there. An unnamed extra is still red below: naming a
    # table Rust-only is the bijection gate's decision, and this gate reads
    # the same map rather than growing a second list.
    rust_only = parse_rust_only(schema)

    checked = 0
    skipped = []
    for multimap, key, value, name in defs:
        if name in rust_only and name not in facts:
            skipped.append(name)
            continue
        if name not in facts:
            failures.append(
                f"{name}: TableDefinition has no matching X-macro/open facts "
                f"(and is not named in RUST_ONLY_TABLES)"
            )
            continue
        flags, cmps, _const, put, packed = facts[name]
        if name in WRITE_NEVER:
            declared, why = WRITE_NEVER[name]
            if put is not PUT_UNSEEN:
                failures.append(
                    f"{name}: declared write-never ({why}) but a `mdb_cursor_put` on its "
                    f"cursor parsed as {put!r} — the table is written again; remove the "
                    f"WRITE_NEVER entry and let the put classify it"
                )
                continue
            put = declared
        key, value = key.strip(), value.strip()
        kinds = {k: fn for k, fn in cmps}

        def want(expected: tuple[str, ...], got, what):
            nonlocal checked
            checked += 1
            if got not in expected:
                failures.append(
                    f"{name}: {what} is `{got}`, must be one of {expected!r} — LMDB flags "
                    f"`{flags.strip()}` / comparators {cmps or 'none'}"
                )

        try:
            exp_key = expected_key_types(flags, kinds, put, packed)
        except UnclassifiedTable as e:
            failures.append(f"{name}: {e} — the gate's classifying fact is missing")
            continue
        if exp_key is not None:
            want(exp_key, key, "key type")
        if multimap:
            failures.append(
                f"{name}: declared as a MultimapTableDefinition, but the catalogue has "
                "no multimap since S-OUT-KI's layout commit — a multimap re-mints its "
                "ordering rule in this gate with its table"
            )

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
        + (f"; {len(skipped)} Rust-only table(s) outside the LMDB-flag domain: "
           f"{', '.join(skipped)}" if skipped else "")
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
