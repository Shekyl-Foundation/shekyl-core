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
        # Every `skl-` name, with the permitted ones enumerated in SKL_ALLOWED
        # below -- deny by default, not allow by default.
        #
        # An earlier version listed the five hostnames that existed when it was
        # written. That gate could only ever catch what its author already knew
        # about: `skl-build`, added next month, would pass in silence, and the
        # rule's claim that an allowlist entry is "a deliberate act reviewed as
        # part of the PR" would be false -- there would be nothing to review.
        # Inverting it makes a new machine identity fail until someone writes
        # down why it is allowed. 47-gate-subject-assertion.mdc is the same
        # instinct one level up: absence of signal is first evidence the gate
        # looked in the wrong place.
        re.compile(r"\bskl-([a-z0-9][a-z0-9-]*)"),
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
        # The whole path component, not `[a-z][a-z0-9_-]*`: that earlier class
        # stopped at the first `.` or capital, so `/home/Rick/` matched as
        # nothing and `/home/rick.dawson/` matched only "rick", both of which
        # are exactly the personal paths this class exists to catch. Matching
        # the component and normalising it below means a name fails unless it
        # is one of the accounts that names nobody.
        # Plausible account characters only. A `/home/` inside a regex literal
        # -- `grep -E '/home/|/Users/'`, as .github/workflows/build.yml does to
        # guard Cargo manifests against absolute paths -- is a pattern, not a
        # path, and stops matching here. So does `/home/$USER` and `/home/<user>`.
        re.compile(r"/home/([A-Za-z0-9._-]+)"),
        "local filesystem path; use a repo-relative path or an env var",
    ),
]

# `skl-` names that are not a machine we run.
#
# Two kinds, and the distinction is the reason this set is small and the
# default is denial:
#   templates  systemd unit templates shipped in utils/fleet. `skl-node@%i` is
#              a service name, instantiated per index on whatever host runs it;
#              it identifies no machine.
#   seeds      public seed identity. A seed exists to be dialed by strangers,
#              its address ships in every binary's `get_seed_nodes`, and its
#              onion is headed there. Publishing the name discloses nothing an
#              intending peer cannot already learn.
#
# Seed *operational state* is not covered by this and the rule still forbids
# it: "the seeds are at A..F" is shipped fact, "this one's config is the
# unedited example and its unrestricted RPC is on :12030" is an exposed admin
# surface. That is class 2, which is prose and not a pattern -- see main().
SKL_ALLOWED = {
    "oe-run",  # a bench data directory under $TMPDIR, not a machine
    "clearnet",  # template: skl-clearnet@.service
    "fleet",  # template: skl-fleet.target
    "node",  # template: skl-node@.service
    "tor",  # template: skl-tor@.service
}
SKL_ALLOWED_PREFIXES = (
    "seed",  # public seed identity: skl-seedaus, skl-seedusw, ...
)

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


def exempt(cls: str, name: str) -> bool:
    """Is this captured name one that identifies nobody?

    Case and punctuation are normalised before the comparison, so `/home/Rick`
    and `/home/rick` are the same question. A name carrying a placeholder
    marker -- `<user>`, `$HOME`, `{{ user }}` -- is documentation, not a path.
    """
    if any(c in name for c in "<>${}"):
        return True
    key = name.strip("/").lower()
    if cls == "path":
        return key in GENERIC_HOMES
    if cls == "host":
        return key in SKL_ALLOWED or key.startswith(SKL_ALLOWED_PREFIXES)
    return False


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
                    if m.groups() and exempt(cls, m.group(1)):
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
