# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Dead-relative-link gate for docs/.
#
# Every markdown link in docs/ whose target is a relative path must resolve to
# a file or directory in this checkout. Link rot in the design docs is not
# cosmetic here: docs/ carries the decision log, the design rounds, and the
# completed-round closeouts that grounding sweeps read as sources -- a dead
# anchor turns a grounded claim into an unverifiable one, and measurement has
# shown the rot regenerates within days of an ordinary file move. This gate
# holds the census shut instead of re-running it by hand.
#
# What counts as a link target, deliberately narrow so the gate cannot cry
# wolf and get deleted (the flagged-legitimate-use failure mode this repo has
# now hit twice in acceptance-criteria gates):
#   - inline markdown links `[text](target)` and `[text](target#fragment)`;
#   - targets that are http(s)/mailto are out of scope (external);
#   - targets must be *path-shaped*: contain a `/` or end in a known source /
#     doc extension. This drops math that pattern-matches links
#     (`E[K](E[K]-1)`) and rustdoc-style intra-doc links quoted in prose
#     (`[x](super::Engine::foo)`).
#   - fragments (`#L123`, `#section`) are not validated -- file existence only.
#   - the resolved path must stay under the repository root. Absolute targets
#     and `..` escapes that leave the checkout are dead, not probes of the
#     CI runner's filesystem.
#
# Deliberate exceptions live in docs/ci/link-allowlist.txt, one path-suffix or
# exact `file:target` pair per line -- for template placeholders that must
# stay literal and for cross-repo sibling links that cannot resolve in a
# single-repo checkout. Every allowlist line must state its reason as an
# inline `#` comment, or the gate rejects the allowlist itself: an exception
# without a reason is how the list grows silently.

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = os.path.join(ROOT, "docs")
ALLOWLIST = os.path.join(DOCS, "ci", "link-allowlist.txt")

LINK_RE = re.compile(r"\]\(([^)#\s]+)(#[^)\s]*)?\)")
PATH_EXTS = (
    ".md", ".mdc", ".rs", ".cpp", ".h", ".hpp", ".c", ".inl", ".py", ".sh",
    ".json", ".yaml", ".yml", ".toml", ".txt", ".png", ".active",
)


def path_shaped(target: str) -> bool:
    if target.startswith(("http://", "https://", "mailto:")):
        return False
    if "::" in target:  # rustdoc intra-doc link quoted in prose
        return False
    return "/" in target or target.endswith(PATH_EXTS)


def in_checkout(resolved: str) -> bool:
    """True iff `resolved` is under ROOT (after normpath). Absolute targets and
    `..` escapes that leave the tree are out of contract."""
    abs_resolved = os.path.abspath(resolved)
    try:
        return os.path.commonpath([ROOT, abs_resolved]) == ROOT
    except ValueError:
        # Different drives on Windows, or empty paths — never in-checkout.
        return False


def load_allowlist() -> tuple[set, set]:
    exact, suffixes = set(), set()
    if not os.path.exists(ALLOWLIST):
        return exact, suffixes
    with open(ALLOWLIST, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "#" not in line:
                print(f"{ALLOWLIST}:{n}: allowlist entry has no reason comment", file=sys.stderr)
                sys.exit(2)
            entry = line.split("#", 1)[0].strip()
            if ":" in entry:
                exact.add(tuple(entry.split(":", 1)))
            else:
                suffixes.add(entry)
    return exact, suffixes


def main() -> int:
    exact, suffixes = load_allowlist()
    dead = []
    for dirpath, _dirs, files in os.walk(DOCS):
        for f in sorted(files):
            if not f.endswith(".md"):
                continue
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, ROOT)
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for m in LINK_RE.finditer(text):
                target = m.group(1)
                if not path_shaped(target):
                    continue
                if (rel, target) in exact or any(target.endswith(s) for s in suffixes):
                    continue
                # Absolute targets: join drops dirpath on POSIX and would probe
                # the runner FS; reject via in_checkout rather than exists().
                resolved = os.path.normpath(os.path.join(dirpath, target))
                if not in_checkout(resolved) or not os.path.exists(resolved):
                    line = text[: m.start()].count("\n") + 1
                    dead.append((rel, line, target))
    for rel, line, target in dead:
        print(f"{rel}:{line}: dead link -> {target}")
    if dead:
        print(f"\n{len(dead)} dead relative link(s). Fix the link, or if the "
              f"exception is deliberate, add it to {os.path.relpath(ALLOWLIST, ROOT)} "
              f"with a reason.", file=sys.stderr)
        return 1
    print("doc links: all relative links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
