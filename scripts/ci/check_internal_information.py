# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Internal-information boundary gate for 37-internal-information-boundary.mdc.
#
# shekyl-core is public. This gate refuses three classes of content:
#
#   host      Foundation host identities (seeds, miners, benchmark devices,
#             web hosts, workstations) and the LAN addressing that reaches them.
#   opstate   Operational state bound to a named host -- reachability, per-host
#             peer limits, RPC exposure, pristine-vs-edited config files.
#   path      Local filesystem paths and personal machine identifiers, whose
#             usual carrier is pasted `cargo` output inside a benchmark capture.
#
# `opstate` is not separately pattern-matched: state is only dangerous when it
# is bound to a host, so refusing the host refuses the pair. The rule carries
# the prose for reviewers.
#
# The allowlist is the rule's carve-out list, by exact path, with a reason on
# every entry. A carve-out asserts the material is already public (the compiled
# seed list ships in every binary) or is not ours (RFC 1918 literals describing
# the protocol; a container's own service account). "It is useful" is not a
# carve-out, which is why adding an entry here shows up in a diff.
#
# Instance of 47-gate-subject-assertion.mdc: zero scannable tracked files means
# the gate found nothing because it looked nowhere, and that is a failure, not
# a pass.

from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# A floor well below the real tree (~thousands of tracked files). Its job is to
# catch a broken enumeration, not to track repository size.
MIN_SCANNED = 200

FORBIDDEN: list[tuple[str, re.Pattern[str], str]] = [
    (
        "host",
        # Enumerated host roles, not a bare `skl-` prefix, for two reasons: the
        # shipped fleet units are `skl-node@`, `skl-tor@`, `skl-clearnet@` and
        # `skl-fleet`, which are generic templates that must keep their names;
        # and `skl-seed*` is public seed identity, carved out below.
        re.compile(r"\bskl-(?:foundation|miner-test|pi|web|dev)\b"),
        "non-public Foundation hostname; write the role (see the rule's table)",
    ),
    # Seed identity -- hostname, clearnet IP, onion address -- is deliberately NOT
    # matched. A seed exists to be dialed by strangers; the addresses ship in every
    # binary's `get_seed_nodes` and the onions are headed there. Publishing them
    # discloses nothing an intending peer cannot already learn, and the onion-to-IP
    # correlation reveals nothing about a host that is publicly reachable on both
    # by design.
    #
    # Seed *operational state* is a different thing and the rule still forbids it:
    # "the seeds are at A..F" is shipped fact, "this one's config is the unedited
    # example and its unrestricted RPC is on :12030" is an exposed admin surface.
    # That class is prose rather than a pattern and falls to review -- see the
    # honesty note in main().
    (
        "host",
        re.compile(r"\bROG2\b"),
        "personal workstation name",
    ),
    (
        "host",
        # 10.10.0.0/16 is the internal estate. RFC 1918 literals that describe
        # the protocol rather than our network use 192.168/10.0 and are not
        # matched here.
        re.compile(r"\b10\.10\.\d{1,3}\.\d{1,3}\b"),
        "internal LAN address",
    ),
    (
        "path",
        # The account name is captured and checked against GENERIC_HOMES below,
        # rather than excluded in the pattern. A real contributor's username is
        # what this class is for, so the allowed set is enumerated and anything
        # outside it fails -- including the next person's.
        re.compile(r"/home/([a-z][a-z0-9_-]*)"),
        "local filesystem path; use a repo-relative path or an env var",
    ),
]

# Home directories that name nobody: service accounts created by our own
# tooling, build-environment accounts, documentation placeholders, and the
# fixed account of a distribution we document against.
GENERIC_HOMES = {
    "alice",  # documentation placeholder, paired with bob
    "amnesia",  # the fixed Tails live-session account
    "bob",  # documentation placeholder
    "gitianuser",  # the gitian deterministic-build account
    "runner",  # GitHub Actions runner
    "shekyl",  # our own service account, on a host this repo does not name
    "ubuntu",  # default cloud-image account
    "user",  # documentation placeholder
}

# (path, class or None for every class, reason). A trailing "/" matches a subtree.
ALLOW: list[tuple[str, str | None, str]] = [
    (
        "src/p2p/net_node.inl",
        "host",
        "the compiled seed list: shipped protocol data, in every node binary, "
        "and bootstrap does not work without it",
    ),
    (
        ".cursor/rules/37-internal-information-boundary.mdc",
        None,
        "the rule states the forbidden patterns in order to forbid them",
    ),
    (
        "scripts/ci/check_internal_information.py",
        None,
        "this gate",
    ),
]


def allowed(path: str, cls: str) -> bool:
    for apath, acls, _reason in ALLOW:
        if acls is not None and acls != cls:
            continue
        if apath.endswith("/"):
            if path.startswith(apath):
                return True
        elif path == apath:
            return True
    return False


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "-C", ROOT, "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def main() -> int:
    files = tracked_files()
    if len(files) < MIN_SCANNED:
        print(
            f"FAIL: enumerated only {len(files)} tracked files (expected "
            f">= {MIN_SCANNED}). The gate looked nowhere; this is not a pass.",
            file=sys.stderr,
        )
        return 2

    violations: list[tuple[str, int, str, str, str]] = []
    scanned = 0

    for rel in files:
        abspath = os.path.join(ROOT, rel)
        try:
            with open(abspath, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable; nothing to read here
        scanned += 1
        for cls, pattern, reason in FORBIDDEN:
            if allowed(rel, cls):
                continue
            for n, line in enumerate(lines, 1):
                for m in pattern.finditer(line):
                    if cls == "path" and m.group(1) in GENERIC_HOMES:
                        continue
                    violations.append((rel, n, cls, reason, line.strip()[:120]))
                    break

    if not violations:
        # Say what the pass does not cover. Two of the rule's three classes are
        # patterns; operational state is prose -- "its config is the unedited
        # example", "unrestricted RPC on :12030" -- and no grep recognises it.
        # A gate that stayed silent about its own blind spot would let a reviewer
        # read this line as "the rule is satisfied", which it does not say.
        print(
            f"OK: {scanned} tracked text files carry no internal hostnames, LAN\n"
            f"    addresses, or local filesystem paths.\n"
            f"    NOT checked: per-host operational state (reachability, RPC\n"
            f"    exposure, pristine-vs-edited configs). That class is prose and\n"
            f"    falls to review -- see the rule, class 2."
        )
        return 0

    by_file: dict[str, int] = {}
    for rel, _n, _cls, _reason, _line in violations:
        by_file[rel] = by_file.get(rel, 0) + 1

    print(
        f"FAIL: {len(violations)} internal identifier(s) in {len(by_file)} file(s).\n"
        f"shekyl-core is public. See .cursor/rules/37-internal-information-boundary.mdc\n"
        f"-- write the role, not the host; internal material belongs in shekyl-dev.\n",
        file=sys.stderr,
    )
    for rel, n, cls, reason, line in violations:
        print(f"  {rel}:{n}: [{cls}] {reason}", file=sys.stderr)
        print(f"      {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
