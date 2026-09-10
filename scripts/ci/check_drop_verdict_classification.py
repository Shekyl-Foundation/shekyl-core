#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# PWD-B7: a rejection that describes OUR STATE must classify itself, so it
# cannot sever the peer that happened to send it. Classification lives at the
# failure site through reject_form / reject_state / reject_internal (Rust
# fold). add_tx must not promote an unclassified check_tx_inputs failure to
# ATTRIBUTABLE_FORM.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DOUBLE_SPEND = re.compile(r"^\s*tvc\.m_double_spend\s*=\s*true\s*;")
STATE_HELPER = "reject_state"
RETURNS = re.compile(r"^\s*return\b")
SOURCES = sorted((ROOT / "src").rglob("*.cpp")) + sorted((ROOT / "src").rglob("*.inl"))

POOL_LOOKUP = "bool tx_memory_pool::have_tx_keyimg_as_spent"
POOL_SPENT_SET = "m_spent_key_images"

CHECK_TX_INPUTS_WRAPPER = (
    "bool Blockchain::check_tx_inputs(transaction& tx, uint64_t& max_used_block_height"
)
CHECK_TX_INPUTS_BODY = (
    "bool Blockchain::check_tx_inputs(transaction& tx, tx_verification_context &tvc,"
)
ADD_TX = "bool tx_memory_pool::add_tx("
ASSERT_MACRO_CALL = re.compile(r"\bCHECK_AND_ASSERT_MES\s*\(")
REJECT_RETURN = re.compile(
    r"^\s*return reject_(form|state|internal|drop)\s*\("
)
PASSTHROUGH = re.compile(r"^\s*if\s*\(\s*!res\s*\)\s*$")
CLASSIFYING_CALLEE = re.compile(
    r"check_archival_(serve_credit_input|bond_post_input)\s*\("
)


def _function_body(lines: list[str], signature: str):
    start = next((i for i, line in enumerate(lines) if signature in line), None)
    if start is None:
        return None, None
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
            print("  false. With it gone this gate cannot check the residual,")
            print("  so it fails rather than passing vacuously.")
            return False

        macro_hits = [
            f"{rel}:{lineno + i}"
            for i, line in enumerate(body)
            if ASSERT_MACRO_CALL.search(line)
        ]
        if macro_hits:
            print(f"FAIL: `CHECK_AND_ASSERT_MES(` inside Blockchain::check_tx_inputs ({label}).")
            print("  That macro returns false without classifying. Expand it")
            print("  and return reject_form/state/internal.")
            for hit in macro_hits:
                print(f"    {hit}")
            ok = False

        bare = []
        for i, line in enumerate(body):
            if "return false" not in line:
                continue
            prev = body[i - 1] if i > 0 else ""
            if PASSTHROUGH.match(prev):
                continue
            if REJECT_RETURN.match(line):
                continue
            window = "".join(body[max(0, i - 6) : i])
            if CLASSIFYING_CALLEE.search(window):
                continue
            bare.append(f"{rel}:{lineno + i}")
        if bare:
            print(f"FAIL: unclassified `return false` in check_tx_inputs ({label}).")
            print("  Every new failure must `return reject_form/state/internal(tvc)`.")
            print("  The `if (!res) return false` passthrough is the only exception.")
            for hit in bare:
                print(f"    {hit}")
            ok = False

        if require_internal and not any("reject_internal" in line for line in body):
            print("FAIL: the 5-arg `check_tx_inputs` wrapper no longer classifies")
            print("  via `reject_internal`.")
            ok = False

    if ok:
        print("PASS: check_tx_inputs failures classify at the site;")
        print("  neither overload returns through an unclassified macro.")
    return ok


def check_add_tx_does_not_promote_form() -> bool:
    path = ROOT / "src" / "cryptonote_core" / "tx_pool.cpp"
    if not path.is_file():
        print(f"FAIL: {path} is missing; add_tx cannot be checked.")
        return False

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lineno, body = _function_body(lines, ADD_TX)
    if lineno is None or body is None:
        print(f"FAIL: `{ADD_TX}` not found in {path.relative_to(ROOT)}.")
        return False

    # The `tx used wrong inputs` arm must not fold ATTRIBUTABLE_FORM over
    # check_tx_inputs. That promotion is the dual default PWD-B7 forbids.
    in_wrong_inputs = False
    for i, line in enumerate(body):
        if "tx used wrong inputs" in line:
            in_wrong_inputs = True
        if in_wrong_inputs and "SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM" in line:
            print("FAIL: add_tx still promotes check_tx_inputs failure to ATTRIBUTABLE_FORM.")
            print(f"  {path.relative_to(ROOT)}:{lineno + i}")
            print("  Classification belongs at the check_tx_inputs return.")
            return False
        if in_wrong_inputs and line.strip() == "}" and i > 0 and "return false" in body[i - 1]:
            break

    print("PASS: add_tx does not promote unclassified check_tx_inputs failures to form.")
    return True


def check_pool_trigger_scope() -> bool:
    path = ROOT / "src" / "cryptonote_core" / "tx_pool.cpp"
    if not path.is_file():
        print(f"FAIL: {path} is missing; the pool double-spend trigger cannot be checked.")
        return False

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = next((i for i, line in enumerate(lines) if line.lstrip().startswith(POOL_LOOKUP)), None)

    if start is None:
        print(f"FAIL: `{POOL_LOOKUP}` not found in {path.relative_to(ROOT)}.")
        print("  PWC-E7 rests on the POOL's double-spend guard consulting the")
        print("  POOL's spent set. With the function gone this gate cannot")
        print("  check that, so it fails rather than passing vacuously.")
        return False

    body = lines[start : start + 40]
    if not any(POOL_SPENT_SET in line for line in body):
        print(f"FAIL: `{POOL_LOOKUP}` no longer reads `{POOL_SPENT_SET}`.")
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

            classified = False
            for j in range(i + 1, min(i + 25, len(lines))):
                if STATE_HELPER in lines[j] or "SHEKYL_DROP_VERDICT_POLICY_OR_STATE" in lines[j]:
                    classified = True
                    break
                if RETURNS.match(lines[j]):
                    break
            if not classified:
                unclassified.append(f"{rel}:{i + 1}")

    if not sites:
        print("FAIL: no `tvc.m_double_spend = true` site found in src/.")
        print("  This gate asserts every double-spend rejection classifies")
        print("  itself POLICY_OR_STATE (PWD-B7). With no site to check it")
        print("  proves nothing, so it fails rather than passing vacuously.")
        return 1

    if unclassified:
        print("FAIL: a double-spend rejection does not classify itself.")
        for site in unclassified:
            print(f"    {site}")
        return 1

    if not check_pool_trigger_scope():
        return 1

    if not check_wrapper_classifies_internal():
        return 1

    if not check_add_tx_does_not_promote_form():
        return 1

    print(f"PASS: {len(sites)} double-spend rejection(s), all classified via {STATE_HELPER}:")
    for site in sites:
        print(f"    {site}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
