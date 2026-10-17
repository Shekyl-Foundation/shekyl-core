#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# A production process spawn in a crate whose image can launch a managed tor
# hands its child standard input, output and error and no other descriptor
# (docs/design/DAEMON_CONFIG_CUTOVER.md section 2.10; the helper is
# rust/shekyl-tor-control-client/src/inherit.rs).
#
# WHY. Rust opens every descriptor close-on-exec; C++ in the same process does
# not promise to (Boost.Asio's sockets, the store's files, a C++ library's
# own). Without the helper in the child's pre_exec, each such descriptor passes
# into the operator's notify command or into the managed tor.
#
# THE RULE. The crates are check_spawn_sites_take_the_lock.py's WATCHED set,
# read from that script, as is its comment-and-string blanking (rule 47), so
# the two gates cannot disagree about which crates or which text count. In each
# watched crate, a production file that builds a process command
# (`Command::new(`, std or tokio, under any alias ending in `Command`) names
# `inherit::` in its code: `inherit::stdio_only(&mut cmd)`, or
# `inherit::StdioOnly` applied in the launch's own pre_exec before it clears
# the one descriptor it keeps. A Windows-only spawn names it too; the call is a
# no-op there.
#
#   Production means under the crate's `src/`, outside any item marked
#   `#[cfg(test)]` or `#[cfg(all(test, ...))]`, and in a module file whose
#   declaration (`mod name;`) is not itself so marked, up the module tree.
#
#   TEST-ONLY SPAWNS ARE NOT THIS GATE'S SUBJECT: `tests/`, `benches/` and
#   `examples/`, a build script, a test module, and a file declared only for
#   tests (the DC-F12 sibling `true` in notify_ffi.rs's tests, the engine's
#   regtest harness). A test binary is not the daemon's image: the C++ whose
#   descriptors this guards is not running there. Their count is printed so a
#   production spawn that moved into a test region is visible in the log.
#
# A file the check does not see: a second command in a file that already
# names `inherit::` once, and a command made by `Command::from`. The unit
# tests beside each call site bite those (notify_ffi.rs, launch.rs).
#
# SUBJECT. The managed launch and the notify runner are production spawn
# files. If either is not found as one, the gate has lost its subject and
# fails.
#
# Usage:  check_spawn_children_inherit_stdio_only.py            # check the tree
#         check_spawn_children_inherit_stdio_only.py --selftest # bite each failure

import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from check_spawn_sites_take_the_lock import (  # noqa: E402
    SKIPPED_DIRS,
    SPAWN,
    WATCHED,
    code_of,
    is_build_script,
)

SUBJECTS = (
    "shekyl-tor-control-client/src/control/launch.rs",
    "shekyl-ffi/src/notify_ffi.rs",
)
HELPER = re.compile(r"\binherit::")
TEST_ATTR = re.compile(r"#\[\s*cfg\s*\(\s*(?:test\b|all\s*\(\s*test\b)")
TEST_DIRS = {"tests", "benches", "examples"}


def attribute_end(code, at):
    """End of the `#[...]` attribute starting at `at`."""
    depth = 0
    for k in range(at, len(code)):
        if code[k] == "[":
            depth += 1
        elif code[k] == "]":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(code)


def item_end(code, at):
    """End of the item starting at `at`: its matching `}`, or its `;` when no
    block opens first."""
    k = at
    while k < len(code) and code[k].isspace():
        k += 1
    while code.startswith("#[", k):
        k = attribute_end(code, k)
        while k < len(code) and code[k].isspace():
            k += 1
    depth = 0
    for j in range(k, len(code)):
        ch = code[j]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ";" and depth == 0:
            return j + 1
        elif ch == "{" and depth == 0:
            braces = 0
            for m in range(j, len(code)):
                if code[m] == "{":
                    braces += 1
                elif code[m] == "}":
                    braces -= 1
                    if braces == 0:
                        return m + 1
            return len(code)
    return len(code)


def production_code(code):
    """`code` with every test-marked item blanked, newlines kept."""
    out = list(code)
    for match in TEST_ATTR.finditer(code):
        end = item_end(code, attribute_end(code, match.start()))
        for k in range(match.start(), end):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def declarers(rel):
    """Candidate files that declare the module `rel` is, with its name."""
    path = pathlib.PurePosixPath(rel)
    if path.name == "mod.rs":
        name, home = path.parent.name, path.parent.parent
    else:
        name, home = path.stem, path.parent
    candidates = [home / "mod.rs", home.parent / f"{home.name}.rs"]
    if home.name == "src":
        candidates = [home / "lib.rs", home / "main.rs"]
    return name, [c.as_posix() for c in candidates]


def declared_for_tests_only(root, rel, seen=None):
    """Whether `rel`'s module, or a module above it, is declared under a test
    attribute."""
    seen = seen or set()
    if rel in seen:
        return False
    seen.add(rel)
    path = pathlib.PurePosixPath(rel)
    if path.name in ("lib.rs", "main.rs") and path.parent.name == "src":
        return False
    name, candidates = declarers(rel)
    declaration = re.compile(rf"\bmod\s+{re.escape(name)}\s*;")
    for parent in candidates:
        source = root / parent
        if not source.is_file():
            continue
        code = code_of(source.read_text(encoding="utf-8", errors="replace"))
        if not declaration.search(code):
            continue
        if not declaration.search(production_code(code)):
            return True
        return declared_for_tests_only(root, parent, seen)
    return False


def classify(root, rel, watched):
    """'production', 'test' or None (not this gate's subject)."""
    parts = pathlib.PurePosixPath(rel).parts
    if len(parts) < 2 or parts[0] not in watched:
        return None
    if is_build_script(rel) or parts[1] in TEST_DIRS:
        return "test"
    if parts[1] != "src":
        return "test"
    if declared_for_tests_only(root, rel):
        return "test"
    return "production"


def check(root, watched, subjects):
    errors = []
    production, tests = [], []
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in SKIPPED_DIRS:
            continue
        rel = rel.as_posix()
        code = code_of(path.read_text(encoding="utf-8", errors="replace"))
        if not SPAWN.search(code):
            continue
        kind = classify(root, rel, watched)
        if kind is None:
            continue
        if kind == "test":
            tests.append(rel)
            continue
        live = production_code(code)
        if not SPAWN.search(live):
            tests.append(rel)
            continue
        production.append(rel)
        if not HELPER.search(live):
            line = live[: SPAWN.search(live).start()].count("\n") + 1
            errors.append(
                f"{rel}:{line}: a production spawn whose child is not limited to "
                "stdio (call inherit::stdio_only, or apply inherit::StdioOnly in "
                "the pre_exec)"
            )
    for subject in subjects:
        if subject not in production:
            errors.append(f"{subject}: not found as a production spawn; the gate has no subject")
    return errors, production, tests



def selftest():
    def tree(files):
        root = pathlib.Path(tempfile.mkdtemp(prefix="spawn-inherit-gate-"))
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    launch = "a/src/launch.rs"
    lib = "a/src/lib.rs"
    good = "fn f() { let mut c = Command::new(x); inherit::stdio_only(&mut c); }"
    bare = "fn f() { let c = Command::new(x); }"
    watched = {"a"}
    subjects = (launch,)
    base = {lib: "mod launch;\nmod other;\n", launch: good}
    cases = {
        "clean": (base, 0),
        "a production spawn without the helper": (
            {**base, "a/src/other.rs": bare},
            1,
        ),
        "the helper named only in a comment": (
            {**base, "a/src/other.rs": bare + "\n// inherit::stdio_only(&mut c)"},
            1,
        ),
        "the helper named only in a string": (
            {**base, "a/src/other.rs": bare + '\nconst S: &str = "inherit::stdio_only";'},
            1,
        ),
        "the helper only inside a test module": (
            {**base, "a/src/other.rs": bare + "\n#[cfg(test)]\nmod tests { fn t() { inherit::stdio_only(&mut c); } }"},
            1,
        ),
        "a spawn inside a test module": (
            {**base, "a/src/other.rs": "#[cfg(test)]\nmod tests {\n" + bare + "\n}"},
            0,
        ),
        "a spawn in a cfg(all(test, unix)) fn": (
            {**base, "a/src/other.rs": "#[cfg(all(test, unix))]\n" + bare},
            0,
        ),
        "a file declared for tests only": (
            {lib: "mod launch;\n#[cfg(test)]\nmod harness;\n", launch: good, "a/src/harness.rs": bare},
            0,
        ),
        "a file under a module declared for tests only": (
            {
                lib: "mod launch;\n#[cfg(test)]\nmod engine;\n",
                launch: good,
                "a/src/engine/mod.rs": "mod e2e;\n",
                "a/src/engine/e2e.rs": bare,
            },
            0,
        ),
        "an integration test": ({**base, "a/tests/t.rs": bare}, 0),
        "a build script": ({**base, "a/build.rs": bare}, 0),
        "an unwatched crate": ({**base, "b/src/lib.rs": bare}, 0),
        "the subject lost its spawn": ({lib: "mod launch;\n", launch: "fn f() {}"}, 1),
        "the subject spawns without the helper": ({lib: "mod launch;\n", launch: bare}, 1),
    }
    failed = False
    for name, (files, want) in cases.items():
        got = len(check(tree(files), watched, subjects)[0])
        if got != want:
            print(f"selftest FAIL: {name}: {got} errors, wanted {want}")
            failed = True
    if failed:
        return 1
    print(f"selftest: {len(cases)} cases bite as expected")
    return 0


def main():
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    root = pathlib.Path(__file__).resolve().parents[2] / "rust"
    errors, production, tests = check(root, WATCHED, SUBJECTS)
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print(
        f"spawn children: {len(production)} production spawn files limit their "
        f"children to stdio; {len(tests)} test-only spawn files not this gate's subject"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
