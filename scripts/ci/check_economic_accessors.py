# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# ESR-16. Production reads EconomicParams through economic_params() and
# RelayPolicy through relay_policy(). A production site that builds
# EconomicParams::default() itself, or keeps a second OnceLock of the
# set, has a second accessor. relay_policy() must be called from a
# production file other than its definition: a definition with no reader
# is not a read.
#
# The economics sim is the sweep: it builds parameter sets. Tests are
# not production. Instance of 47-gate-subject-assertion.mdc.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUST = os.path.join(ROOT, "rust")
ACCESSOR = os.path.join("shekyl-economics", "src", "params.rs")
RELAY_DEF = os.path.join("shekyl-economics", "src", "relay_policy.rs")
MIN_FILES = 200
SKIP_CRATES = {
    "shekyl-economics-sim",
    "shekyl-staking-sim",
    "shekyl-wss-q1b-bench",
}


def strip_cfg_test(text: str) -> str:
    """Drop `#[cfg(test)]` items. A scan of test bodies is not a production read."""
    out = []
    depth = 0
    skip_until = None
    arm = False
    for line in text.splitlines(keepends=True):
        opens = line.count("{")
        closes = line.count("}")
        if skip_until is not None:
            depth += opens - closes
            if depth <= skip_until:
                skip_until = None
            continue
        compact = line.replace(" ", "")
        if "#[cfg(test)]" in compact or compact.startswith("#[test]"):
            arm = True
            depth += opens - closes
            continue
        if arm:
            arm = False
            base = depth
            depth += opens - closes
            if depth > base:
                skip_until = base
            continue
        depth += opens - closes
        out.append(line)
    return "".join(out)


def is_test_path(rel: str) -> bool:
    """A test tree, a test module, or the named test-support module.

    A path component is `tests` or ends in `_tests`. A file is `tests.rs`,
    `*_tests.rs`, `*_test.rs`, or `test_support.rs`. A substring match is
    not a test: `attestation_wire.rs` is production.
    """
    parts = rel.split(os.sep)
    name = parts[-1]
    if (
        name == "tests.rs"
        or name == "test_support.rs"
        or name.endswith("_tests.rs")
        or name.endswith("_test.rs")
    ):
        return True
    return any(part == "tests" or part.endswith("_tests") for part in parts[:-1])


_CFG_TEST_MOD = re.compile(
    r"(?P<attr>(?:#\[[^\]]*\]\s*)+)"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z0-9_]+)\s*;",
    re.MULTILINE,
)


def _split_top(body: str) -> list[str]:
    """Split `body` on commas that are not inside parentheses or quotes."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = False
    for ch in body:
        if quote:
            buf.append(ch)
            if ch == '"':
                quote = False
            continue
        if ch == '"':
            quote = True
            buf.append(ch)
            continue
        if ch == "(":
            depth += 1
            buf.append(ch)
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
            continue
        if ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _cfg_bodies(attr: str) -> list[str]:
    """The interiors of every `cfg(...)` in an attribute list."""
    bodies: list[str] = []
    index = 0
    while True:
        found = attr.find("cfg(", index)
        if found < 0:
            return bodies
        start = found + 4
        depth = 1
        quote = False
        cursor = start
        while cursor < len(attr) and depth:
            ch = attr[cursor]
            if quote:
                if ch == '"':
                    quote = False
            elif ch == '"':
                quote = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            cursor += 1
        bodies.append(attr[start : cursor - 1].strip())
        index = cursor


def _false_without_test(expr: str) -> bool:
    """True when `expr` is false in every build where `test` is false.

    Other atoms stay unknown. `all` is false when any argument is. `any`
    is false only when every argument is. `not` inverts the always-true
    case. An atom is that predicate only when it is `test` itself.
    """
    expr = expr.strip()
    if expr.startswith("all(") and expr.endswith(")"):
        return any(_false_without_test(part) for part in _split_top(expr[4:-1]))
    if expr.startswith("any(") and expr.endswith(")"):
        return all(_false_without_test(part) for part in _split_top(expr[4:-1]))
    if expr.startswith("not(") and expr.endswith(")"):
        return _true_without_test(expr[4:-1])
    return expr == "test"


def _true_without_test(expr: str) -> bool:
    """True when `expr` is true in every build where `test` is false."""
    expr = expr.strip()
    if expr.startswith("all(") and expr.endswith(")"):
        parts = _split_top(expr[4:-1])
        return all(_true_without_test(part) for part in parts)
    if expr.startswith("any(") and expr.endswith(")"):
        return any(_true_without_test(part) for part in _split_top(expr[4:-1]))
    if expr.startswith("not(") and expr.endswith(")"):
        return _false_without_test(expr[4:-1])
    return False


def _cfg_requires_test(attr: str) -> bool:
    """True when the attribute list cannot hold in a non-test build.

    Attributes combine by conjunction, so one `cfg` that requires `test`
    is enough. `cfg(any(test, feature = "…"))` can hold with the feature
    alone, and stays in the scan.
    """
    return any(_false_without_test(body) for body in _cfg_bodies(attr))


def cfg_test_module_files() -> set[str]:
    """Files owned by a module declared under a `test` cfg.

    The declaration lives on the parent (`#[cfg(test)] mod name;`), so the
    file itself carries no marker. A `#[path]` on that declaration is the
    same module.
    """
    owned: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(RUST):
        dirnames[:] = [d for d in dirnames if d != "target"]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            text = open(path, encoding="utf-8").read()
            for match in _CFG_TEST_MOD.finditer(text):
                if not _cfg_requires_test(match.group("attr")):
                    continue
                attr = match.group("attr").replace(" ", "")
                mod = match.group("name")
                owned.add(os.path.normpath(os.path.join(dirpath, f"{mod}.rs")))
                owned.add(os.path.normpath(os.path.join(dirpath, mod, "mod.rs")))
                path_attr = re.search(r'#\[path="([^"]+)"\]', attr)
                if path_attr is not None:
                    owned.add(os.path.normpath(os.path.join(dirpath, path_attr.group(1))))
    return owned


def production_files() -> list[str]:
    test_modules = cfg_test_module_files()
    found = []
    for dirpath, dirnames, filenames in os.walk(RUST):
        rel_dir = os.path.relpath(dirpath, RUST)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != "target" and d not in SKIP_CRATES]
            continue
        dirnames[:] = [d for d in dirnames if d != "target"]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.normpath(os.path.join(dirpath, name))
            rel = os.path.relpath(path, RUST)
            if is_test_path(rel) or path in test_modules:
                continue
            found.append(path)
    return found


def main() -> int:
    files = production_files()
    if len(files) < MIN_FILES:
        print(
            f"economic-accessor gate scanned {len(files)} rust files; "
            f"expected at least {MIN_FILES}. The subject is missing.",
            file=sys.stderr,
        )
        return 1
    saw_accessor = False
    saw_relay = False
    saw_relay_read = False
    failures = []
    for path in files:
        rel = os.path.relpath(path, RUST)
        text = open(path, encoding="utf-8").read()
        if rel == ACCESSOR and "fn economic_params(" in text:
            saw_accessor = True
        if rel == RELAY_DEF and "fn relay_policy(" in text:
            saw_relay = True
        body = strip_cfg_test(text)
        if rel != RELAY_DEF and "relay_policy()" in body:
            saw_relay_read = True
        if "OnceLock<RelayPolicy>" in body:
            failures.append(f"{rel}: RelayPolicy is the const shipped policy")
        if rel == ACCESSOR or rel == RELAY_DEF:
            continue
        if "EconomicParams::default()" in body:
            failures.append(f"{rel}: production builds EconomicParams::default()")
        if "OnceLock<EconomicParams>" in body:
            failures.append(f"{rel}: a second EconomicParams OnceLock")
    if not saw_accessor or not saw_relay or not saw_relay_read:
        print(
            "economic-accessor gate did not see economic_params(), "
            "relay_policy(), and a production read of relay_policy(). "
            "The subject is missing.",
            file=sys.stderr,
        )
        return 1
    if failures:
        print("production reads EconomicParams through economic_params():", file=sys.stderr)
        for item in failures:
            print(f"  {item}", file=sys.stderr)
        return 1
    print(f"economic accessors: {len(files)} production rust files, one of each")
    return 0


def selftest() -> int:
    sample = "fn live() { let _ = EconomicParams::default(); }\n"
    if "EconomicParams::default()" not in strip_cfg_test(sample):
        print("selftest: a live default() was stripped", file=sys.stderr)
        return 1
    tested = "#[cfg(test)]\nfn t() { let _ = EconomicParams::default(); }\n"
    if "EconomicParams::default()" in strip_cfg_test(tested):
        print("selftest: a cfg(test) default() survived", file=sys.stderr)
        return 1
    checks = {
        os.path.join("shekyl-archival-retention", "src", "attestation_wire.rs"): False,
        os.path.join("shekyl-chain-ingest", "src", "test_support.rs"): True,
        os.path.join("foo", "vectors_tests", "bar.rs"): True,
        os.path.join("shekyl-foo", "tests", "bar.rs"): True,
        os.path.join("shekyl-foo", "src", "tests.rs"): True,
        os.path.join("shekyl-foo", "src", "foo_tests.rs"): True,
        os.path.join("shekyl-foo", "src", "foo_test.rs"): True,
        os.path.join("shekyl-foo", "src", "live.rs"): False,
    }
    for rel, want_test in checks.items():
        if is_test_path(rel) != want_test:
            print(f"selftest: {rel} classified incorrectly", file=sys.stderr)
            return 1
    sample_mod = "/// note\n#[cfg(test)]\nmod regtest_e2e;\n#[cfg(not(test))]\nmod live;\n"
    found = {
        match.group("name")
        for match in _CFG_TEST_MOD.finditer(sample_mod)
        if _cfg_requires_test(match.group("attr"))
    }
    if found != {"regtest_e2e"}:
        print(f"selftest: cfg(test) modules were {found}", file=sys.stderr)
        return 1
    cfg_cases = {
        "#[cfg(test)]": True,
        "#[cfg(not(test))]": False,
        "#[cfg(all(test, unix))]": True,
        "#[cfg(all(unix, test))]": True,
        "#[cfg(all(test, feature = \"pipeline\"))]": True,
        '#[cfg(any(test, feature = "production"))]': False,
        "#[cfg(any(test, test))]": True,
        "#[cfg(not(not(test)))]": True,
        '#[cfg(all(any(test, feature = "x"), test))]': True,
    }
    for attr, want in cfg_cases.items():
        if _cfg_requires_test(attr) != want:
            print(f"selftest: {attr} classified incorrectly", file=sys.stderr)
            return 1
    open_mod = (
        '#[cfg(any(test, feature = "production"))]\nmod open;\n'
        '#[cfg(all(test, feature = "pipeline"))]\nmod closed;\n'
    )
    open_found = {
        match.group("name")
        for match in _CFG_TEST_MOD.finditer(open_mod)
        if _cfg_requires_test(match.group("attr"))
    }
    if open_found != {"closed"}:
        print(f"selftest: feature-or-test modules were {open_found}", file=sys.stderr)
        return 1
    print("economic-accessor selftest passed")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
