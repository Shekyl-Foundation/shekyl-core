# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for check_drs_c_surface_map.py.
#
# WHY THIS FILE EXISTS. That gate has now been wrong twice in the same way: a
# receiver shape its derivation could not follow, silently absent from the
# vocabulary, with the bijection green over the gap. Round 1 was `db->` (the
# gate matched only `m_db->`); round 2 was `this->m_db->` and reference-typed
# aliases called through `.`. Hand-run negative controls caught neither,
# because they were written from the same mental model as the derivation.
#
# So the shapes are pinned as CASES, in both directions: every form that must
# be COLLECTED, every form that must be REFUSED, and — the ones that actually
# bite — the near-misses that must do NEITHER. A regex added to the gate
# without a case added here is how round 2 happened.

import importlib.util
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_drs_c_surface_map.py"
_spec = importlib.util.spec_from_file_location("drs_c_gate", GATE)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

FAILURES = []
CHECKS = 0


def check(label, got, want):
    global CHECKS
    CHECKS += 1
    if got != want:
        FAILURES.append(f"{label}\n      expected: {want!r}\n      got:      {got!r}")


def vocab(src):
    return gate.collect_vocabulary(src, gate.derive_aliases(src))


def refusals(src):
    return [what for _line, what, _snip in
            gate.unhandled_shapes(src, gate.derive_aliases(src))]


# ---------------------------------------------------------------- collection

check("pointer alias via ->",
      vocab("BlockchainDB* m_db;\nvoid f(){ m_db->height(); }"), {"height"})

check("second alias derived from a parameter",
      vocab("static void fill(BlockchainDB *db){ db->get_tx_blob(); }"), {"get_tx_blob"})

# The round-2 regression: `(?<![\w>])` treated `>` as a boundary, so a
# receiver reached through another arrow vanished. The ORIGINAL `m_db->` token
# match caught these, so the round-1 fix made the gate blinder here.
check("arrow-qualified receiver `this->m_db->`",
      vocab("BlockchainDB* m_db;\nvoid f(){ this->m_db->is_open(); }"), {"is_open"})

check("arrow-qualified receiver `obj->db->`",
      vocab("BlockchainDB *db;\nvoid f(){ obj->db->sync(); }"), {"sync"})

# A reference alias is declared with `&` and called with `.`. Deriving the name
# but collecting only `->` is worse than not deriving it: it looks covered.
check("reference alias via .",
      vocab("void f(BlockchainDB &r){ r.batch_stop(); }"), {"batch_stop"})

check("cv-qualified declaration derives the NAME, not `const`",
      sorted(gate.derive_aliases("BlockchainDB* const m_db;")), ["m_db"])

check("operator follows the SIGIL, not the call site",
      gate.derive_aliases("BlockchainDB* p; BlockchainDB &r;"),
      {"p": {"->"}, "r": {"."}})

check("a name declared both ways carries both operators",
      gate.derive_aliases("BlockchainDB* d; void f(BlockchainDB &d);"), {"d": {"->", "."}})

check("whitespace and newlines between receiver and operator",
      vocab("BlockchainDB* m_db;\nvoid f(){ m_db\n  ->get_block_weights(); }"),
      {"get_block_weights"})

check("several calls on several aliases",
      vocab("BlockchainDB* m_db;\nstatic void fill(BlockchainDB *db){ db->a(); }\n"
            "void f(){ m_db->b(); m_db->c(); }"), {"a", "b", "c"})

# ----------------------------------------------------------- near-misses
# These must be collected by NOTHING and refused by NOTHING. A gate that fires
# on correct code teaches the author to write it less carefully.

check("a different pointer whose name ENDS with an alias is not the alias",
      vocab("BlockchainDB* m_db;\nvoid f(){ m_tx_pool->add(); }"), set())

check("a different pointer whose name STARTS with an alias is not the alias",
      vocab("BlockchainDB *db;\nvoid f(){ db_something->add(); }"), set())

check("`auto` binding a call RESULT is not a store binding",
      refusals("BlockchainDB* m_db;\nvoid f(){ auto h = m_db->height(); }"), [])

check("...and the call it binds is still collected",
      vocab("BlockchainDB* m_db;\nvoid f(){ auto h = m_db->height(); }"), {"height"})

check("a const auto& binding a call result is not a store binding",
      refusals("BlockchainDB* m_db;\nvoid f(){ const auto &o = m_db->get_output_key(a); }"), [])

# ------------------------------------------------------------------ refusals

check("bare `get_db` anywhere is refused, not only when a call follows",
      len(refusals("BlockchainDB* m_db;\nvoid f(){ BlockchainDB &r = get_db(); r.height(); }")), 1)

check("`get_db()` with an immediate call is refused",
      len(refusals("BlockchainDB* m_db;\nvoid f(){ get_db().height(); }")), 1)

check("`auto` bound to the store is refused",
      len(refusals("BlockchainDB* m_db;\nvoid f(){ auto *a = m_db; a->height(); }")), 1)

check("`auto &` bound to a dereferenced store is refused",
      len(refusals("BlockchainDB* m_db;\nvoid f(){ auto &a = *m_db; }")), 1)

check("dereferenced call `(*db).x` is refused",
      len(refusals("BlockchainDB* m_db;\nvoid f(){ (*m_db).height(); }")), 1)

# THE HOLE THE ROUND-2 FIX ITSELF HAD: refusals were written against a
# hardcoded `(?:m_db|db)` while the collection was derived. A third alias was
# collected but never refused — the original defect, reintroduced one level up.
check("refusals apply to a DERIVED third alias, not a hardcoded pair",
      len(refusals("BlockchainDB* store;\nvoid f(){ auto *a = store; }")), 1)

check("dereference refusal also applies to a derived third alias",
      len(refusals("BlockchainDB* store;\nvoid f(){ (*store).height(); }")), 1)

check("no declarations at all -> no aliases (caller must refuse)",
      gate.derive_aliases("void f(){ something->height(); }"), {})

check("empty alias set cannot make the auto/deref refusals match everything",
      gate.unhandled_shapes("void f(){ auto *a = x; (*y).z(); }", {}), [])

# ------------------------------------------------------------- bijection legs

DOC_OK = """### 3.5 DRS-C surface map (3 methods from `blockchain.cpp`)

| Surface | Role | # | Methods | Order | Note |
| --- | --- | --- | --- | --- | --- |
| **S-A** | Alpha | 2 | `alpha` `beta` | 1 | n |
| **S-B** | Beta | 1 | `gamma` | 2 | n |

### 3.6 Next
"""
VOC = {"alpha", "beta", "gamma"}


def partition_failures(doc, voc=VOC):
    section = gate.slice_section(doc)
    if section is None:
        return ["NO SECTION"]
    return gate.check_partition(section, voc)[0]


check("clean partition passes", partition_failures(DOC_OK), [])

check("uncovered method fails",
      any("in NO surface" in f for f in
          partition_failures(DOC_OK, VOC | {"delta"})), True)

check("phantom method fails",
      any("NOT reached" in f for f in
          partition_failures(DOC_OK.replace("`gamma`", "`ghost`"))), True)

check("duplicate assignment fails",
      any("assigned to BOTH" in f for f in
          partition_failures(DOC_OK.replace("| 1 | `gamma` |", "| 1 | `alpha` |"))), True)

check("row count mismatch fails",
      any("declares 2 methods and lists 1" in f for f in
          partition_failures(DOC_OK.replace("`alpha` `beta`", "`alpha`"),
                             {"alpha", "gamma"})), True)

check("heading count mismatch fails",
      any("heading says 9 methods" in f for f in
          partition_failures(DOC_OK.replace("(3 methods", "(9 methods"))), True)

check("missing heading count fails",
      any("does not state a method count" in f for f in
          partition_failures(DOC_OK.replace("### 3.5 DRS-C surface map (3 methods",
                                            "### 3.5 DRS-C surface map"))), True)

check("a section with no rows is refused, not vacuously satisfied",
      any("no surface rows" in f for f in
          partition_failures("### 3.5 DRS-C surface map (3 methods)\n\nprose\n\n### 3.6 x\n")),
      True)

check("§3.5 absent is detected as a missing subject",
      gate.slice_section("### 3.4 Other\n\ntext\n"), None)

# ------------------------------------------------- cross-document figures
# The heading's count was gated while three sibling documents restated it
# ungated, and every restatement drifted to 97 while the tree moved to 102.
# `read` is injected so these run without touching the repo.

GOOD = "the map covers 102 store methods over 272 store call sites"


def xrefs(texts, size=102, sites=272):
    """texts: {filename -> text or None}, defaulting to the good figure."""
    return gate.check_cross_references(
        lambda p: texts.get(p.name, GOOD), size, sites)


check("every cross-reference agreeing with the derivation passes",
      xrefs({}), [])

check("a cross-reference stating the wrong method count fails",
      any("says 97 store methods" in f for f in
          xrefs({"IMPLEMENTATION_INDEX.md": "surfaces (97 store methods)"})), True)

check("a cross-reference stating the wrong call-site count fails",
      any("says 253 store call sites" in f for f in
          xrefs({"DAEMON_REDB_STORE.md": GOOD.replace("272", "253")})), True)

check("a cross-reference that states NO figure fails as a missing subject",
      any("states no `N store methods` figure" in f for f in
          xrefs({"CONSENSUS_STORE_RECONCILIATION.md": "prose with no figure"})), True)

check("a missing cross-reference file fails rather than passing by absence",
      any("a cross-reference subject does not exist" in f for f in
          xrefs({"IMPLEMENTATION_INDEX.md": None})), True)

check("one stale occurrence among several correct ones still fails",
      any("says 99 store methods" in f for f in
          xrefs({"DAEMON_REDB_STORE.md": GOOD + " and elsewhere 99 store methods"})), True)

check("all three declared files are actually read",
      len(xrefs({"DAEMON_REDB_STORE.md": "x", "CONSENSUS_STORE_RECONCILIATION.md": "x",
                 "IMPLEMENTATION_INDEX.md": "x"})), 3)

# Every SPELLING of the figure, because keying on one phrasing is how the
# cross-reference leg shipped green over two live restatements.

for phrase, label in (("102 store methods", "store methods"),
                      ("102 DB methods", "DB methods"),
                      ("102 `m_db->` methods", "m_db-> methods"),
                      ("102 `db->` methods", "db-> methods"),
                      ("**102** store methods", "bolded"),
                      ("102  store  methods", "extra whitespace")):
    check(f"spelling captured: {label}",
          gate.CROSS_REF_METHODS_RE.findall(f"the map covers {phrase} today"), ["102"])

for phrase, label in (("97 store methods", "stale store methods"),
                      ("97 DB methods", "stale DB methods"),
                      ("97 `m_db->` methods", "stale m_db-> methods")):
    check(f"stale spelling still FAILS: {label}",
          any("says 97" in f for f in xrefs({"IMPLEMENTATION_INDEX.md": phrase})), True)

# A broadened matcher earns its keep only if it stays off other figures in the
# very same documents. These are real neighbours, not invented ones.
for phrase, label in (("rehost ~3k / 77 methods", "E-7 gather shell (77 methods)"),
                      ("against 48 virtual archival methods", "base-class archival methods"),
                      ("landed nine methods", "no digit at all"),
                      ("102 methods from `blockchain.cpp`", "bare heading form (HEAD_RE owns it)")):
    check(f"near-miss NOT captured: {label}",
          gate.CROSS_REF_METHODS_RE.findall(phrase), [])

check("an unrelated method count does not trip the cross-reference leg",
      xrefs({"DAEMON_REDB_STORE.md": "102 store methods, and separately 77 methods for E-7"}),
      [])

check("call-site count is derived, not the method count",
      gate.count_call_sites("BlockchainDB* m_db;\nvoid f(){ m_db->a(); m_db->a(); m_db->b(); }",
                            {"m_db": {"->"}}), 3)


if FAILURES:
    print(f"check_drs_c_surface_map self-test FAILED ({len(FAILURES)}/{CHECKS}):\n",
          file=sys.stderr)
    for f in FAILURES:
        print(f"  - {f}\n", file=sys.stderr)
    sys.exit(1)
print(f"check_drs_c_surface_map self-test: {CHECKS} cases pass "
      f"(collection, near-misses, refusals over DERIVED aliases, bijection legs)")
