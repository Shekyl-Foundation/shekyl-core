# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Claim-era basename gate: docs/design/ must not grow CONFIDENTIAL_STAKING.md
# or a txin_stake_claim_v2 spec. The claim-era model is deleted.

from __future__ import annotations

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DESIGN = os.path.join(ROOT, "docs", "design")
FORBIDDEN = ("CONFIDENTIAL_STAKING.md",)


def main() -> int:
    if not os.path.isdir(DESIGN):
        print("claim-era: docs/design/ is missing", file=sys.stderr)
        return 2
    hits = []
    for f in sorted(os.listdir(DESIGN)):
        if f in FORBIDDEN:
            hits.append(f"docs/design/{f}: claim-era spec must not return")
        if "txin_stake_claim" in f.lower():
            hits.append(f"docs/design/{f}: claim-era filename")
    if hits:
        for h in hits:
            print(h)
        print(f"\n{len(hits)} claim-era basename(s) in docs/design/.",
              file=sys.stderr)
        return 1
    print("claim-era: docs/design/ has no CONFIDENTIAL_STAKING / txin_stake_claim spec")
    return 0


if __name__ == "__main__":
    sys.exit(main())
