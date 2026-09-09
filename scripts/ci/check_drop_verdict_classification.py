#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# PWD-B7: a rejection that describes OUR STATE must classify itself, so it
# cannot sever the peer that happened to send it.
#
# WHY A GATE AND NOT A COMMENT. The implementation left two bounded residual
# risks, both smaller copies of the defect the unit removed.
# `Blockchain::check_tx_inputs` has dozens of `return false` sites.
# Classifying all of them affirmatively would be strictly sound, but it is a
# large blast radius in consensus-adjacent C++ that the Rust port exists to
# avoid paying for twice -- so its caller (`tx_pool.cpp`, the "tx used wrong
# inputs" arm) classifies ATTRIBUTABLE_FORM by default, and the arms that
# describe our own chain classify themselves as POLICY_OR_STATE before
# returning. The fold in `shekyl-peer-policy` then keeps the precise reading.
#
# That left two ways to reintroduce the bug:
#
#   1. add an arm inside `check_tx_inputs` that consults our chain state and
#      forget to classify it -- it inherits the caller's ATTRIBUTABLE_FORM;
#   2. return false through `CHECK_AND_ASSERT_MES`, which cannot write a
#      verdict, so the same fold promotes OUR invariant failure into a
#      severing one. The 5-arg wrapper's "internal error: max used block
#      index" arm was this hole (Bugbot on #674).
#
# WHY THIS INSTRUMENT AND NOT A COUNT. Pinning the number of `return false`
# sites was the other candidate. It was rejected: a legitimate refactor moves
# that count, so the pin would be moved routinely, and a pin that is moved
# routinely is not read. This asserts the properties actually at issue --
# every double-spend verdict is state-describing, and neither overload
# returns through a macro that cannot classify -- so it fires only on the
# case it exists for, in both directions:
#
#   * a new `m_double_spend` arm with no classification FAILS;
#   * deleting the classification from an existing arm FAILS;
#   * deleting every arm FAILS, by the rule-47 subject assertion below,
#     because a shrinking subject is the direction nobody watches;
#   * reintroducing `CHECK_AND_ASSERT_MES` inside either overload FAILS;
#   * deleting the wrapper's INTERNAL_FAILURE classification FAILS.
#
# SCOPE, stated so it is not read as more than it is. This gate covers the
# double-spend class, which is the one identifiable by a field the code
# already sets, and the macro-return class, which is identifiable by a
# token. It does NOT prove every state-describing rejection in
# `check_tx_inputs` is classified; no grep can, because "describes our state"
# is not a syntactic property. It closes the named residuals, not the
# category.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The marker: a rejection reporting a key image already spent in OUR chain or
# pool. Reorg-dependent, node-local, and legitimate on a peer's view.
DOUBLE_SPEND = re.compile(r"^\s*tvc\.m_double_spend\s*=\s*true\s*;")
# The classification it must carry before it returns.
STATE_VERDICT = "SHEKYL_DROP_VERDICT_POLICY_OR_STATE"
# A return ends the window: the verdict must be recorded before control leaves.
RETURNS = re.compile(r"^\s*return\b")

# Every C++ translation unit that can set the flag. Kept as a directory sweep
# rather than a file list so a fourth site in a new file is covered on arrival.
SOURCES = sorted((ROOT / "src").rglob("*.cpp")) + sorted((ROOT / "src").rglob("*.inl"))


# ── The SECOND residue: the trigger's scope, not the verdict ────────────────
#
# A verdict type preserves THAT a no-drop occurs. It does not preserve THE
# SCOPE OF THE CONDITION that produces one -- and here the scope is the whole
# point.
#
# PWC-E7/§5.2 checked, rather than assumed, that the pool's double-spend guard
# consults the POOL's `m_spent_key_images`: tx1 sitting in the pool when a
# conflicting tx2 arrives, which is the Dandelion++ arm of the eclipse attack
# (Shi et al. §III-C). A chain-spent-only trigger would not see that case at
# all. So a port that faithfully inherits `DropVerdict`, passes every verdict
# test above, and narrows this trigger to the chain would look fully
# discharged while silently regressing exactly what the guard is for.
#
# Nothing in the verdict type excludes that, because the fold governs verdict
# TRANSITIONS rather than trigger SCOPE. This is the narrowest honest pin
# available without a live pool: the pool's own lookup must read the pool's
# own spent set.
#
# WHAT THIS DOES NOT PROVE, stated so the gate is not read as more than it is:
# it asserts the pool consultation is PRESENT, not that it is REACHED. A
# refactor that adds a chain check in front and leaves this one dead would
# pass. Closing that needs a live-pool behavioural test (tx1 admitted, tx2
# conflicting, assert no-drop), which needs a Blockchain and a DB -- core_tests
# territory, not this gate's.
POOL_LOOKUP = "bool tx_memory_pool::have_tx_keyimg_as_spent"
POOL_SPENT_SET = "m_spent_key_images"

# The 5-arg wrapper is the one add_tx actually calls. Its leftover
# CHECK_AND_ASSERT_MES could not write a verdict; the 4-arg body had a
# second copy of the same shape. Both overloads must classify on every
# false return they own, which a macro return cannot do.
CHECK_TX_INPUTS_WRAPPER = (
    "bool Blockchain::check_tx_inputs(transaction& tx, uint64_t& max_used_block_height"
)
CHECK_TX_INPUTS_BODY = (
    "bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc,"
)
INTERNAL_VERDICT = "SHEKYL_DROP_VERDICT_INTERNAL_FAILURE"
# Invocation, not the token: a comment naming the macro must not fail the
# gate, and CHECK_AND_ASSERT_MES_L1 / _THROW_MES must not either.
ASSERT_MACRO_CALL = re.compile(r"\bCHECK_AND_ASSERT_MES\s*\(")


def _function_body(lines: list[str], signature: str):
    start = next((i for i, line in enumerate(lines) if signature in line), None)
    if start is None:
        return None, None
    # Brace-match from the first `{` on or after the signature. Nested
    # functions are not a concern: these are member definitions.
    depth = 0
    begun = False
    body: list[str] = []
    for i in range(start, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                begun = True
            elif ch == "}":
                depth -= 1
        if begun:
            body.append(lines[i])
            if depth == 0:
                return start + 1, body
    return start + 1, body


def check_wrapper_classifies_internal() -> bool:
    path = ROOT / "src" / "cryptonote_core" / "blockchain.cpp"
    if not path.is_file():
        print(f"FAIL: {path} is missing; the check_tx_inputs wrapper cannot be checked.")
        return False

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    rel = path.relative_to(ROOT)
    ok = True

    for label, signature, require_internal in (
        ("5-arg wrapper", CHECK_TX_INPUTS_WRAPPER, True),
        ("4-arg body", CHECK_TX_INPUTS_BODY, False),
    ):
        lineno, body = _function_body(lines, signature)
        if lineno is None or body is None:
            print(f"FAIL: `{signature}` not found in {rel}.")
            print("  add_tx keys its drop verdict on this function returning")
            print("  false. With it gone this gate cannot check the residual")
            print("  Bugbot named, so it fails rather than passing vacuously.")
            return False

        macro_hits = [
            f"{rel}:{lineno + i}"
            for i, line in enumerate(body)
            if ASSERT_MACRO_CALL.search(line)
        ]
        if macro_hits:
            print(f"FAIL: `CHECK_AND_ASSERT_MES(` inside Blockchain::check_tx_inputs ({label}).")
            print()
            print("  That macro returns false without writing tvc.m_drop_verdict,")
            print("  so add_tx's ATTRIBUTABLE_FORM fold promotes OUR invariant")
            print("  failure into a severing one -- the hole PWD-B7 exists to")
            print("  close. Expand it and classify the arm.")
            print()
            for hit in macro_hits:
                print(f"    {hit}")
            ok = False

        if require_internal and not any(INTERNAL_VERDICT in line for line in body):
            print("FAIL: the 5-arg `check_tx_inputs` wrapper no longer classifies")
            print(f"  `{INTERNAL_VERDICT}`.")
            print()
            print("  Its leftover arm is `max_used_block_height < m_db->height()`:")
            print("  OUR chain versus an index WE computed. The sender is not")
            print("  answerable. Without this classification, add_tx's coarse")
            print("  form fold severs an innocent peer (PWD-B7).")
            ok = False

    if ok:
        print("PASS: neither check_tx_inputs overload returns through an unclassified macro,")
        print(f"  and the 5-arg wrapper classifies `{INTERNAL_VERDICT}`.")
    return ok


def check_pool_trigger_scope() -> bool:
    path = ROOT / "src" / "cryptonote_core" / "tx_pool.cpp"
    if not path.is_file():
        print(f"FAIL: {path} is missing; the pool double-spend trigger cannot be checked.")
        return False

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    # `lstrip`, not `startswith`: the definition is indented inside the
    # namespace, and an anchored match would report the subject absent -- a
    # gate failing for the wrong reason (rule 46).
    start = next((i for i, line in enumerate(lines) if line.lstrip().startswith(POOL_LOOKUP)), None)

    # Rule 47 again: the subject must exist before its property is asserted.
    if start is None:
        print(f"FAIL: `{POOL_LOOKUP}` not found in {path.relative_to(ROOT)}.")
        print("  PWC-E7 rests on the POOL's double-spend guard consulting the")
        print("  POOL's spent set -- a pool-held conflict, not only a")
        print("  chain-spent image. With the function gone this gate cannot")
        print("  check that, so it fails rather than passing vacuously.")
        return False

    body = lines[start : start + 40]
    if not any(POOL_SPENT_SET in line for line in body):
        print(f"FAIL: `{POOL_LOOKUP}` no longer reads `{POOL_SPENT_SET}`.")
        print()
        print("  Narrowing this trigger to chain-spent images would leave every")
        print("  verdict test green while removing the case the guard exists")
        print("  for: a conflicting tx2 arriving while tx1 sits in OUR POOL --")
        print("  the Dandelion++ arm of the eclipse attack, where the")
        print("  double-spend conflict is what drops the connections.")
        print(f"  See PWC-E7 and section 5.2 of docs/design/P2P_1_WIRE_CENSUS.md.")
        return False

    print(f"PASS: the pool double-spend trigger still reads `{POOL_SPENT_SET}`.")
    return True


def main() -> int:
    sites = []
    unclassified = []

    for path in SOURCES:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines):
            if not DOUBLE_SPEND.match(line):
                continue
            rel = path.relative_to(ROOT)
            sites.append(f"{rel}:{i + 1}")

            # Scan forward to the return that ends this rejection.
            classified = False
            for j in range(i + 1, min(i + 25, len(lines))):
                if STATE_VERDICT in lines[j]:
                    classified = True
                    break
                if RETURNS.match(lines[j]):
                    break
            if not classified:
                unclassified.append(f"{rel}:{i + 1}")

    # ── Rule 47: assert the subject exists ───────────────────────────────
    # An empty sweep would otherwise report a clean pass while proving
    # nothing -- the absence of a signal is first evidence the subject is
    # absent, not that the property holds.
    if not sites:
        print("FAIL: no `tvc.m_double_spend = true` site found in src/.")
        print("  This gate asserts every double-spend rejection classifies")
        print("  itself POLICY_OR_STATE (PWD-B7). With no site to check it")
        print("  proves nothing, so it fails rather than passing vacuously.")
        print("  If the field was deliberately retired, retire this gate in")
        print("  the same change and say so.")
        return 1

    if unclassified:
        print("FAIL: a double-spend rejection does not classify itself.")
        print()
        print("  A key image spent in OUR chain is reorg-dependent and")
        print("  node-local: the same transaction can be perfectly valid on")
        print("  the sender's view. Under PWD-B7 it must NOT sever the peer.")
        print(f"  Set `{STATE_VERDICT}` on `tvc.m_drop_verdict` (through")
        print("  `shekyl_drop_verdict_combine`) before returning, or the")
        print("  caller's coarser ATTRIBUTABLE_FORM will sever an honest peer.")
        print()
        for site in unclassified:
            print(f"    {site}")
        return 1

    if not check_pool_trigger_scope():
        return 1

    if not check_wrapper_classifies_internal():
        return 1

    print(f"PASS: {len(sites)} double-spend rejection(s), all classified {STATE_VERDICT}:")
    for site in sites:
        print(f"    {site}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
