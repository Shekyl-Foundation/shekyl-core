# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-0 slice B: the redb schema map is a BIJECTION with the censused LMDB
# inventory. Every table in `SHEKYL_LMDB_TABLES` has exactly one
# `redb::TableDefinition` (or `MultimapTableDefinition`), and every definition
# has exactly one X-macro table. Both directions, no duplicates on either side.
#
# WHY THE X-MACRO IS THE SOURCE. Walking `BlockchainDB`'s virtual interface
# is not a denominator, because a table can exist without being on it. The
# instance that proved it: until 2026-09-13 the settlement write path existed
# only on `BlockchainLMDB` (zero occurrences in blockchain_db.h and testdb.h),
# so a schema built from the abstract interface would have shipped without a
# write path LMDB has. SO-D8 has since promoted the four methods onto
# `BlockchainDB`; that closes the instance, not the class, and this gate keeps
# reading the macro.
#
# THIS GATE CHECKS NAMES, NOT TYPES. Ordering is `check_redb_schema_key_types.py`
# in the same workflow; comparator evidence is in `lmdb_order`'s tests (pinned
# against a transcription of the C++ over 4 000 pairs); class evidence is
# per-row in LMDB_WRITE_ATOMICITY_AUDIT.md §12. "49/49 mapped" is a claim on
# one axis.
#
# Instance of 47-gate-subject-assertion.mdc: an empty parse on either side has
# an empty difference, which is indistinguishable from a clean run.

#
# RUST-ONLY TABLES (S-CHAIN-W commit 1, SCW-11). The mirror assumption retires
# one table at a time, never as a mode switch: `schema.rs` carries a named map
# `RUST_ONLY_TABLES: &[(&str, &str)]` of tables that have NO X-macro twin, each
# with the sentence that says why it exists. A TableDefinition with neither a
# twin nor an entry in that map is still red with the extra-leg's original
# refusal below — "this is how a plausible concept becomes an invented table" —
# because that catch is the one that has to survive the transition it is now
# in. The map asserts its own subject too (rule 47): an entry naming a table
# that IS in the X-macro, or that has no definition, or with an empty reason,
# is red. `--selftest` proves each refusal fires on the input built to trip it.

#
# MIRRORED IN ANOTHER FILE (S-POOL, SPL-2). The third direction: an X-macro
# table whose redb twin is a definition in ANOTHER file of the crate — the pool
# file (`DAEMON_REDB_STORE.md` §5.1: the pool does not live in the consensus
# store file). `schema.rs` carries `MIRRORED_ELSEWHERE: &[(&str, &str, &str)]`
# as `(lmdb_name, twin_name, reason)`. Every entry must be in the X-macro, must
# NOT be defined in `schema.rs`, and its twin must be a definition in
# `pool/schema.rs`; and a censused table missing from `schema.rs` is red unless
# it is named here. The class table is still the LMDB inventory — a mirrored
# table keeps its class row — so that check is unchanged. Self-asserting like
# the Rust-only map: an entry naming a table not in the X-macro, one that IS
# defined here, one whose twin no other file defines, one with a token for
# a reason, or two entries that name one twin, is red.
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LMDB = ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp"
SCHEMA = ROOT / "rust/shekyl-chain-store/src/schema.rs"
POOL_SCHEMA = ROOT / "rust/shekyl-chain-store/src/pool/schema.rs"
CLASSES = ROOT / "rust/shekyl-chain-store/src/accumulator/class.rs"

MACRO_RE = re.compile(r"#define SHEKYL_LMDB_TABLES\(X\)(.*?)\n\n", re.S)
ENTRY_RE = re.compile(r'X\(\s*\w+\s*,\s*"([^"]+)"\s*\)')
DEF_RE = re.compile(r'(?:Multimap)?TableDefinition::new\("([^"]+)"\)')
RUST_ONLY_RE = re.compile(r"pub const RUST_ONLY_TABLES\s*:[^=]*=\s*&\[(.*?)\];", re.S)
MIRRORED_RE = re.compile(r"pub const MIRRORED_ELSEWHERE\s*:[^=]*=\s*&\[(.*?)\];", re.S)
# One string literal inside a const-tuple field. A reason may be several,
# joined, including a `\` newline continuation that the parser elides.
LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"', re.S)


def dupes(names):
    seen, out = set(), []
    for n in names:
        if n in seen:
            out.append(n)
        seen.add(n)
    return out


def parse_const_tuples(schema: str, const_name: str, const_re, width: int):
    """The body of `pub const NAME = &[ (...), ... ]` as a list of string
    tuples of `width`. The last field may be adjacent literals or a
    backslash continuation; every other byte of the body must be a tuple,
    a comma, a comment or whitespace. A missing const is a missing subject
    (rule 47), and an entry the pattern cannot see is a refusal — `findall`
    would skip it and report a clean map it had shortened."""
    m = const_re.search(schema)
    if not m:
        raise ValueError(
            f"schema.rs: `pub const {const_name}` did not parse — subject missing")
    names = r'\s*,\s*'.join(['"([a-z_0-9]+)"'] * (width - 1))
    entry_re = re.compile(
        rf'\(\s*{names}\s*,\s*((?:"(?:[^"\\]|\\.)*"\s*)+)\s*,?\s*\)', re.S)
    body = m.group(1)
    out = []
    pos = 0
    while pos < len(body):
        ws = re.compile(r"\s+|//[^\n]*\n?|,").match(body, pos)
        if ws:
            pos = ws.end()
            continue
        entry = entry_re.match(body, pos)
        if not entry:
            snippet = body[pos:pos + 60].strip().splitlines()[0] if body[pos:].strip() else ""
            raise ValueError(
                f"{const_name}: unparsed content at offset {pos}: `{snippet}` — every "
                f"entry must be {width} string fields, names [a-z0-9_], reason last")
        fields = list(entry.groups()[:-1])
        reason = re.sub(r"\\\n\s*", "", "".join(LIT_RE.findall(entry.group(width))))
        fields.append(reason.strip())
        out.append(tuple(fields))
        pos = entry.end()
    return out


def parse_rust_only(schema: str):
    """`RUST_ONLY_TABLES` as {name: reason}. Raises if the const is absent —
    the map is part of the gate's subject now that one Rust-only table
    exists, so a missing const is a missing subject, not an empty map."""
    rows = parse_const_tuples(schema, "RUST_ONLY_TABLES", RUST_ONLY_RE, 2)
    out = {}
    for name, reason in rows:
        if name in out:
            raise ValueError(f"RUST_ONLY_TABLES: `{name}` listed twice")
        out[name] = reason
    return out


def parse_mirrored(schema: str):
    """`MIRRORED_ELSEWHERE` as {lmdb_name: (twin_name, reason)}. Raises if the
    const is absent — since S-POOL two censused tables live in another file,
    so the map is part of the subject."""
    rows = parse_const_tuples(schema, "MIRRORED_ELSEWHERE", MIRRORED_RE, 3)
    out = {}
    for name, twin, reason in rows:
        if name in out:
            raise ValueError(f"MIRRORED_ELSEWHERE: `{name}` listed twice")
        out[name] = (twin, reason)
    return out


def check(censused, defined, classed, rust_only, mirrored=None, pool_defined=()):
    """The set arithmetic over the three surfaces plus the Rust-only map.
    Returns the failure list; empty means the surfaces agree."""
    failures = []
    for label, names in (("SHEKYL_LMDB_TABLES", censused), ("schema.rs", defined)):
        d = dupes(names)
        if d:
            failures.append(f"{label}: duplicate table name(s): {', '.join(sorted(set(d)))}")

    # THIRD SURFACE: slice A's accumulator class table. lib.rs requires slice B's
    # names to be bijection-pinned against it, and two lanes maintaining one
    # table list is precisely where drift lives — so it is checked here rather
    # than asserted in prose. Rust-only tables have no class row: their
    # exclusion is the reason in the map, and the class table stays the LMDB
    # inventory.
    d = dupes(classed)
    if d:
        failures.append(f"TABLE_CLASSES: duplicate table name(s): {', '.join(sorted(set(d)))}")
    only_class = sorted(set(classed) - set(censused))
    only_macro = sorted(set(censused) - set(classed))
    if only_class:
        failures.append(
            f"{len(only_class)} name(s) in TABLE_CLASSES are NOT in the X-macro:\n    "
            + ", ".join(only_class))
    if only_macro:
        failures.append(
            f"{len(only_macro)} censused table(s) carry NO accumulator class:\n    "
            + ", ".join(only_macro)
            + "\n    Slice A assigns one of five tokens to every table; a gap here means "
              "the two slices disagree about the inventory.")

    mirrored = mirrored or {}
    missing = sorted(set(censused) - set(defined) - set(mirrored))
    extra = sorted(set(defined) - set(censused))
    if missing:
        failures.append(
            f"{len(missing)} censused table(s) have NO redb TableDefinition:\n    "
            + ", ".join(missing)
            + "\n    Every table in the X-macro must be mapped; a gap here ships a store "
              "missing a table LMDB has. A table whose twin lives in another file of the "
              "crate is named in MIRRORED_ELSEWHERE with the twin and the reason.")

    # FIFTH SURFACE: the mirrored-elsewhere map (S-POOL). Each entry is a
    # censused table with no definition here and a twin defined in the pool
    # file; anything else is a stale or invented entry.
    not_censused = sorted(set(mirrored) - set(censused))
    if not_censused:
        failures.append(
            f"{len(not_censused)} MIRRORED_ELSEWHERE entr(y/ies) name a table that is NOT in the "
            f"X-macro:\n    " + ", ".join(not_censused)
            + "\n    The map is for censused tables whose twin is elsewhere; a name LMDB never "
              "had belongs in RUST_ONLY_TABLES of the file that defines it, or nowhere.")
    also_here = sorted(set(mirrored) & set(defined))
    if also_here:
        failures.append(
            f"{len(also_here)} MIRRORED_ELSEWHERE entr(y/ies) name a table that IS defined in "
            f"schema.rs:\n    " + ", ".join(also_here)
            + "\n    A table cannot be both here and elsewhere; one of the two is the twin.")
    twinless = sorted(n for n, (twin, _) in mirrored.items() if twin not in pool_defined)
    if twinless:
        failures.append(
            f"{len(twinless)} MIRRORED_ELSEWHERE entr(y/ies) name a twin that pool/schema.rs "
            f"does NOT define:\n    "
            + ", ".join(f"{n} -> {mirrored[n][0]}" for n in twinless)
            + "\n    The twin is a definition that exists; a stale entry is a moved table "
              "whose forwarding address outlived it.")
    owners = {}
    for name, (twin, _) in mirrored.items():
        owners.setdefault(twin, []).append(name)
    shared = sorted(twin for twin, names in owners.items() if len(names) > 1)
    if shared:
        failures.append(
            f"{len(shared)} MIRRORED_ELSEWHERE twin(s) are named by more than one censused "
            f"table:\n    "
            + ", ".join(f"{twin} <- {', '.join(sorted(owners[twin]))}" for twin in shared)
            + "\n    The map is a bijection: one censused table, one twin.")
    unreasoned_m = sorted(n for n, (_, r) in mirrored.items() if len(r.split()) < 8)
    if unreasoned_m:
        failures.append(
            f"{len(unreasoned_m)} MIRRORED_ELSEWHERE entr(y/ies) carry no reason (a sentence, "
            f"not a token):\n    " + ", ".join(unreasoned_m))

    # FOURTH SURFACE: the Rust-only map. Every extra definition must be named
    # there with a reason; everything named there must be an extra definition.
    unnamed = sorted(set(extra) - set(rust_only))
    if unnamed:
        failures.append(
            f"{len(unnamed)} TableDefinition(s) name a table that is NOT in the X-macro "
            f"and NOT in RUST_ONLY_TABLES:\n    "
            + ", ".join(unnamed)
            + "\n    This is how a plausible concept becomes an invented table — check "
              "whether it is really a row inside another table. If it is genuinely a "
              "table LMDB never had, name it in RUST_ONLY_TABLES with the sentence that "
              "says why.")
    rust_only_censused = sorted(set(rust_only) & set(censused))
    if rust_only_censused:
        failures.append(
            f"{len(rust_only_censused)} RUST_ONLY_TABLES entr(y/ies) name a table that IS in the X-macro:\n    "
            + ", ".join(rust_only_censused)
            + "\n    A mirrored table is not Rust-only; the map is for tables with no twin.")
    dangling = sorted(set(rust_only) - set(defined))
    if dangling:
        failures.append(
            f"{len(dangling)} RUST_ONLY_TABLES entr(y/ies) have NO TableDefinition:\n    "
            + ", ".join(dangling)
            + "\n    The map names definitions that exist; a stale entry is a deleted table "
              "whose reason outlived it.")
    unreasoned = sorted(n for n, r in rust_only.items() if len(r.split()) < 8)
    if unreasoned:
        failures.append(
            f"{len(unreasoned)} RUST_ONLY_TABLES entr(y/ies) carry no reason (a sentence, "
            f"not a token):\n    " + ", ".join(unreasoned))
    return failures


def main():
    failures = []
    for p in (LMDB, SCHEMA, CLASSES):
        if not p.is_file():
            failures.append(f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist")
    if failures:
        report(failures)

    src = LMDB.read_text(encoding="utf-8")
    m = MACRO_RE.search(src)
    if not m:
        report([f"{LMDB.name}: SHEKYL_LMDB_TABLES macro did not parse — subject missing"])
    censused = ENTRY_RE.findall(m.group(1))

    schema = SCHEMA.read_text(encoding="utf-8")
    defined = DEF_RE.findall(schema)
    try:
        rust_only = parse_rust_only(schema)
        mirrored = parse_mirrored(schema)
    except ValueError as e:
        report([str(e)])
    if not POOL_SCHEMA.is_file():
        report([f"{POOL_SCHEMA.relative_to(ROOT)}: missing — the mirrored twins' file does not exist"])
    pool_defined = DEF_RE.findall(POOL_SCHEMA.read_text(encoding="utf-8"))
    if not pool_defined:
        report([f"{POOL_SCHEMA.name}: parsed ZERO TableDefinitions — the twins' subject is missing"])

    # Subject assertions: an empty side covers trivially.
    if not censused:
        failures.append(f"{LMDB.name}: parsed ZERO tables from SHEKYL_LMDB_TABLES")
    if not defined:
        failures.append(f"{SCHEMA.name}: parsed ZERO TableDefinitions")
    if failures:
        report(failures)

    ctext = CLASSES.read_text(encoding="utf-8")
    cstart = ctext.find("pub const TABLE_CLASSES")
    if cstart < 0:
        report([f"{CLASSES.name}: TABLE_CLASSES did not parse — third surface missing"])
    block = ctext[cstart:]
    block = block[: block.index("\n];")]
    classed = re.findall(r'"([a-z_0-9]+)"', block)
    if not classed:
        report([f"{CLASSES.name}: parsed ZERO class entries — third surface missing"])

    report(check(censused, defined, classed, rust_only, mirrored, pool_defined))
    here = len(set(defined) & set(censused))
    print(f"redb schema bijection: {len(censused)} censused LMDB tables <-> "
          f"{here} mirrored redb table definitions in schema.rs + {len(mirrored)} mirrored in "
          f"the pool file ({', '.join(f'{n}->{t}' for n, (t, _) in sorted(mirrored.items()))}) "
          f"<-> {len(classed)} accumulator classes; "
          f"+ {len(rust_only)} Rust-only table(s) with a named reason "
          f"({', '.join(sorted(rust_only))}); {len(defined)} definitions total; "
          f"no duplicates, no unnamed extras, no gaps in any direction")


def report(failures):
    if failures:
        print("redb schema bijection FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


# --- self-test: every refusal fires on the input built to trip it ---------

_OK_SCHEMA = '''
pub const RUST_ONLY_TABLES: &[(&str, &str)] = &[(
    "undo_log",
    "the pop journal: one row of pre-images per height, replacing the C++ \\
     journals",
)];
'''


def _expect(name, failures, needle):
    if not any(needle in f for f in failures):
        raise SystemExit(
            f"selftest {name}: expected a refusal mentioning {needle!r}, got:\n  "
            + "\n  ".join(failures or ["<clean>"]))


def selftest():
    censused = ["a", "b", "c"]
    classed = ["a", "b", "c"]
    rust_only = parse_rust_only(_OK_SCHEMA)
    if rust_only != {"undo_log": "the pop journal: one row of pre-images per height, replacing the C++ journals"}:
        raise SystemExit(f"selftest parse: got {rust_only!r}")

    clean = check(censused, ["a", "b", "c", "undo_log"], classed, rust_only)
    if clean:
        raise SystemExit("selftest clean: expected no failures, got:\n  " + "\n  ".join(clean))
    also_clean = check(censused, censused, classed, {})
    if also_clean:
        raise SystemExit("selftest mirror-only: expected no failures, got:\n  " + "\n  ".join(also_clean))

    _expect("unnamed extra keeps the original refusal",
            check(censused, ["a", "b", "c", "undo_log", "invented"], classed, rust_only),
            "This is how a plausible concept becomes an invented table")
    _expect("unnamed extra names the table",
            check(censused, ["a", "b", "c", "invented"], classed, rust_only),
            "invented")
    _expect("map entry that is mirrored",
            check(censused, ["a", "b", "c"], classed, {"a": "eight words of reason are required here now"}),
            "IS in the X-macro")
    _expect("map entry with no definition",
            check(censused, ["a", "b", "c"], classed, rust_only),
            "have NO TableDefinition")
    _expect("map entry with a token for a reason",
            check(censused, ["a", "b", "c", "undo_log"], classed, {"undo_log": "journal"}),
            "carry no reason")
    _expect("missing definition",
            check(censused, ["a", "b", "undo_log"], classed, rust_only),
            "have NO redb TableDefinition")
    _expect("class table drift",
            check(censused, ["a", "b", "c", "undo_log"], ["a", "b"], rust_only),
            "carry NO accumulator class")
    _expect("duplicate definition",
            check(censused, ["a", "a", "b", "c", "undo_log"], classed, rust_only),
            "duplicate table name")
    try:
        parse_rust_only("pub const OTHER: u8 = 1;")
    except ValueError as e:
        if "subject missing" not in str(e):
            raise SystemExit(f"selftest absent map: wrong message {e}")
    else:
        raise SystemExit("selftest absent map: expected a refusal")
    # A malformed entry beside a valid one must be refused, not skipped: with
    # `findall` the hyphenated name below vanished and the map read as one
    # clean entry (PR #757 review).
    malformed = '''
pub const RUST_ONLY_TABLES: &[(&str, &str)] = &[
    ("undo_log", "the pop journal: one row of pre-images per height, replacing the C++ journals"),
    ("bad-name", "a reason long enough to pass the eight-word floor of the reason check"),
];
'''
    try:
        parse_rust_only(malformed)
    except ValueError as e:
        if "unparsed content" not in str(e) or "bad-name" not in str(e):
            raise SystemExit(f"selftest unparsed entry: wrong message {e}")
    else:
        raise SystemExit("selftest unparsed entry: expected a refusal")
    # Comments and trailing commas between entries are fine.
    commented = '''
pub const RUST_ONLY_TABLES: &[(&str, &str)] = &[
    // the journal
    ("undo_log", "the pop journal: one row of pre-images per height, replacing the C++ journals"),
];
'''
    if parse_rust_only(commented) != {
        "undo_log": "the pop journal: one row of pre-images per height, replacing the C++ journals"
    }:
        raise SystemExit("selftest commented map: did not parse")
    # The mirrored-elsewhere direction (S-POOL).
    mirrored_ok = {"c": ("pool_c", "the c table lives in the pool file for a reason of eight words")}
    clean_m = check(censused, ["a", "b", "undo_log"], classed, rust_only, mirrored_ok, ["pool_c"])
    if clean_m:
        raise SystemExit("selftest mirrored clean: expected no failures, got:\n  " + "\n  ".join(clean_m))
    _expect("mirrored entry not censused",
            check(censused, ["a", "b", "c", "undo_log"], classed, rust_only,
                  {"zzz": ("pool_z", "a reason long enough to pass the eight-word floor here")}, ["pool_z"]),
            "NOT in the X-macro")
    _expect("mirrored entry also defined here",
            check(censused, ["a", "b", "c", "undo_log"], classed, rust_only, mirrored_ok, ["pool_c"]),
            "IS defined in schema.rs")
    _expect("mirrored entry with no twin",
            check(censused, ["a", "b", "undo_log"], classed, rust_only, mirrored_ok, []),
            "does NOT define")
    _expect("mirrored entry with a token for a reason",
            check(censused, ["a", "b", "undo_log"], classed, rust_only, {"c": ("pool_c", "pool")}, ["pool_c"]),
            "carry no reason")
    both = "a reason long enough to pass the eight-word floor here"
    _expect("two censused tables name one twin",
            check(censused, ["a", "undo_log"], classed, rust_only,
                  {"b": ("pool_c", both), "c": ("pool_c", both)}, ["pool_c"]),
            "one twin")
    parsed = parse_mirrored('''
pub const MIRRORED_ELSEWHERE: &[(&str, &str, &str)] = &[
    // the pool
    ("txpool_meta", "pool_meta", "the pool is not consensus state and lives in \\
     its own file"),
];
''')
    if parsed != {"txpool_meta": ("pool_meta", "the pool is not consensus state and lives in its own file")}:
        raise SystemExit(f"selftest mirrored parse: got {parsed!r}")
    try:
        parse_mirrored("pub const OTHER: u8 = 1;")
    except ValueError as e:
        if "subject missing" not in str(e):
            raise SystemExit(f"selftest absent mirrored map: wrong message {e}")
    else:
        raise SystemExit("selftest absent mirrored map: expected a refusal")
    print("redb schema bijection selftest: 3 clean shapes pass, 14 refusals fire")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()
