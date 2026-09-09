#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# PWD-B7: a rejection that describes OUR STATE must classify itself, so it
# cannot sever the peer that happened to send it.
#
# WHY A GATE AND NOT A COMMENT. The implementation left one bounded residual
# risk, and it is a smaller copy of the defect the unit removed.
# `Blockchain::check_tx_inputs` has 57 `return false` sites. Classifying all
# of them affirmatively would be strictly sound, but it is a large blast
# radius in consensus-adjacent C++ that the Rust port exists to avoid paying
# for twice -- so its caller (`tx_pool.cpp`, the "tx used wrong inputs" arm)
# classifies ATTRIBUTABLE_FORM by default, and the arms that describe our own
# chain classify themselves as POLICY_OR_STATE before returning. The fold in
# `shekyl-peer-policy` then keeps the precise reading.
#
# That leaves exactly one way to reintroduce the bug: add an arm inside
# `check_tx_inputs` that consults our chain state and forget to classify it.
# It would then inherit the caller's ATTRIBUTABLE_FORM and sever an honest
# peer whose transaction merely conflicts with our view. Its only guard would
# be that someone remembers -- and a warning is not a control.
#
# WHY THIS INSTRUMENT AND NOT A COUNT. Pinning the number of `return false`
# sites was the other candidate. It was rejected: a legitimate refactor moves
# that count, so the pin would be moved routinely, and a pin that is moved
# routinely is not read. This asserts the property actually at issue -- every
# double-spend verdict is state-describing -- so it fires only on the case it
# exists for, in both directions:
#
#   * a new `m_double_spend` arm with no classification FAILS;
#   * deleting the classification from an existing arm FAILS;
#   * deleting every arm FAILS, by the rule-47 subject assertion below,
#     because a shrinking subject is the direction nobody watches.
#
# SCOPE, stated so it is not read as more than it is. This gate covers the
# double-spend class, which is the one identifiable by a field the code
# already sets. It does NOT prove every state-describing rejection in
# `check_tx_inputs` is classified; no grep can, because "describes our state"
# is not a syntactic property. It closes the named residual, not the category.

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

    print(f"PASS: {len(sites)} double-spend rejection(s), all classified {STATE_VERDICT}:")
    for site in sites:
        print(f"    {site}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
