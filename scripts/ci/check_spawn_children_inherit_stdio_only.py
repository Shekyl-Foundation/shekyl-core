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
# WHY. Rust opens every descriptor close-on-exec; a C library in the same
# process does not promise to (the store's, a TLS library's own). Without the
# helper in the child's pre_exec, each such descriptor passes into the
# operator's notify command or into the managed tor.
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
#   Production means under the crate's `src/`, outside any item whose
#   `#[cfg(...)]` cannot hold in a shipped build, and in a module file whose
#   declaration (`mod name;`) is not itself so marked, up the module tree. A
#   shipped build has `test` off and `feature = "unpinned-tor-for-tests"`
#   off. The predicate is evaluated with those two false and every other
#   option unknown: `cfg(test)`, `cfg(all(test, unix))` and
#   `cfg(any(test, feature = "unpinned-tor-for-tests"))` come out false and
#   are test-only; `cfg(any(unix, feature = "unpinned-tor-for-tests"))` and
#   `cfg(all(unix, not(feature = "unpinned-tor-for-tests")))` come out
#   unknown and are checked. A predicate the gate cannot parse is checked.
#   `unpinned-tor-for-tests` is shekyl-tor-control-client's `cfg(test)`
#   across a crate boundary (`cfg(test)` does not cross it).
#   `check_test_only_features.py` refuses every edge that is not a
#   dev-dependency, so the feature is not in a shipped binary.
#
#   TEST-ONLY SPAWNS ARE NOT THIS GATE'S SUBJECT: `tests/`, `benches/` and
#   `examples/`, a build script, a test module, and a file declared only for
#   tests (the DC-F12 sibling `true` in notify.rs's tests, the engine's
#   regtest harness). A test binary is not the daemon's image: the libraries
#   whose descriptors this guards are not running there. Their count is printed so a
#   production spawn that moved into a test region is visible in the log.
#
# A file the check does not see: a second command in a file that already
# names `inherit::` once, and a command made by `Command::from`. The unit
# tests beside each call site bite those (notify.rs, launch.rs).
#
# SUBJECT. The managed launch and the notify runner are production spawn
# files. If either is not found as one, the gate has lost its subject and
# fails.
#
# Usage:  check_spawn_children_inherit_stdio_only.py            # check the tree
#         check_spawn_children_inherit_stdio_only.py --selftest # bite each failure

import atexit
import pathlib
import re
import shutil
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
    "shekyl-daemon/src/notify.rs",
)
HELPER = re.compile(r"\binherit::")
# The options a shipped build has off (see the module comment). An item under
# a cfg that is false with these off is test-only.
OFF_IN_SHIPPED = {("test", None), ("feature", "unpinned-tor-for-tests")}
CFG_TOKEN = re.compile(r'\s*(?:([A-Za-z_][A-Za-z0-9_]*)|"((?:[^"\\]|\\.)*)"|([(),=]))')


def cfg_tokens(text):
    """The tokens of a cfg predicate, or None when `text` holds anything else."""
    tokens, i = [], 0
    while i < len(text):
        if text[i:].strip() == "":
            break
        match = CFG_TOKEN.match(text, i)
        if match is None:
            return None
        ident, string, punct = match.groups()
        tokens.append(("ident", ident) if ident else ("str", string) if string is not None else (punct, punct))
        i = match.end()
    return tokens


def cfg_value(tokens):
    """The predicate's value in a shipped build: False, or None when it may
    hold. Raises ValueError on a form it does not know.

    Three-valued: an option in OFF_IN_SHIPPED is False and any other option
    is unknown (None). `all` is False when a part is False and True when
    every part is True; `any` is True when a part is True and False when
    every part is False; `not` swaps True and False. Anything else is None.
    """
    at = 0

    def take(kind):
        nonlocal at
        if at >= len(tokens) or tokens[at][0] != kind:
            raise ValueError(kind)
        at += 1
        return tokens[at - 1][1]

    def predicate():
        nonlocal at
        name = take("ident")
        if at < len(tokens) and tokens[at][0] == "(":
            if name not in ("all", "any", "not"):
                raise ValueError(name)
            take("(")
            parts = []
            while tokens[at][0] != ")":
                parts.append(predicate())
                if tokens[at][0] == ",":
                    take(",")
            take(")")
            if name == "not":
                if len(parts) != 1:
                    raise ValueError("not")
                return {True: False, False: True, None: None}[parts[0]]
            if name == "all":
                return False if False in parts else (True if all(p is True for p in parts) else None)
            return True if True in parts else (False if all(p is False for p in parts) else None)
        value = None
        if at < len(tokens) and tokens[at][0] == "=":
            take("=")
            value = take("str")
        return False if (name, value) in OFF_IN_SHIPPED else None

    try:
        result = predicate()
    except IndexError as exc:
        raise ValueError("truncated") from exc
    if at != len(tokens):
        raise ValueError("trailing")
    return result


def test_only_cfg(original, start, end):
    """Whether the attribute `original[start:end]` is a `#[cfg(...)]` that is
    false in a shipped build."""
    match = re.match(r"#\[\s*cfg\s*\((.*)\)\s*\]\Z", original[start:end], re.S)
    if match is None:
        return False
    tokens = cfg_tokens(match.group(1))
    if tokens is None:
        return False
    try:
        return cfg_value(tokens) is False
    except ValueError:
        return False


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


def production_code(original):
    """`original` with every test-marked item blanked, newlines kept.

    A `#[cfg]` counts only where `#[` survives comment and string blanking, so
    a cfg written in a comment or a string does not hide a spawn. The
    attribute is then read from `original`: the feature name lives in a
    string, and the blanked text no longer contains it.
    """
    code = code_of(original)
    out = list(code)
    for match in re.finditer(r"#\[", code):
        start = match.start()
        attribute = attribute_end(code, start)
        if not test_only_cfg(original, start, attribute):
            continue
        end = item_end(code, attribute)
        for k in range(start, end):
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
        original = source.read_text(encoding="utf-8", errors="replace")
        code = code_of(original)
        if not declaration.search(code):
            continue
        if not declaration.search(production_code(original)):
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
        original = path.read_text(encoding="utf-8", errors="replace")
        code = code_of(original)
        if not SPAWN.search(code):
            continue
        kind = classify(root, rel, watched)
        if kind is None:
            continue
        if kind == "test":
            tests.append(rel)
            continue
        live = production_code(original)
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
        # Removed when the selftest exits, whatever a case found.
        atexit.register(shutil.rmtree, root, True)
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
        "a file declared under the unpinned-tor test feature": (
            {
                lib: 'mod launch;\n#[cfg(any(test, feature = "unpinned-tor-for-tests"))]\nmod outside;\n',
                launch: good,
                "a/src/outside.rs": bare,
            },
            0,
        ),
        "a spawn under any(test, unix) is production": (
            {**base, "a/src/other.rs": "#[cfg(any(test, unix))]\n" + bare},
            1,
        ),
        "a spawn under any(unix, the feature) is production": (
            {**base, "a/src/other.rs": '#[cfg(any(unix, feature = "unpinned-tor-for-tests"))]\n' + bare},
            1,
        ),
        "a spawn under all(unix, not(the feature)) is production": (
            {
                **base,
                "a/src/other.rs": '#[cfg(all(unix, not(feature = "unpinned-tor-for-tests")))]\n' + bare,
            },
            1,
        ),
        "a spawn under not(test) is production": (
            {**base, "a/src/other.rs": "#[cfg(not(test))]\n" + bare},
            1,
        ),
        "a spawn under another feature is production": (
            {**base, "a/src/other.rs": '#[cfg(feature = "other")]\n' + bare},
            1,
        ),
        "a spawn under a cfg the gate cannot read is production": (
            {**base, "a/src/other.rs": "#[cfg(test, unix)]\n" + bare},
            1,
        ),
        "a spawn under all(unix, any(test, the feature)) is test-only": (
            {
                **base,
                "a/src/other.rs": '#[cfg(all(unix, any(test, feature = "unpinned-tor-for-tests")))]\n' + bare,
            },
            0,
        ),
        "a spawn under not(any(not(test), unix)) is test-only": (
            {**base, "a/src/other.rs": "#[cfg(not(any(not(test), unix)))]\n" + bare},
            0,
        ),
        "a feature-gated spawn does not cover a production one": (
            {
                **base,
                "a/src/other.rs": '#[cfg(feature = "unpinned-tor-for-tests")]\n' + bare + "\n" + bare,
            },
            1,
        ),
        "a commented feature cfg does not hide a production spawn": (
            {
                **base,
                "a/src/other.rs": '// #[cfg(feature = "unpinned-tor-for-tests")]\n' + bare,
            },
            1,
        ),
        "the feature named only in a string does not hide a production spawn": (
            {
                **base,
                "a/src/other.rs": (
                    'const S: &str = "#[cfg(feature = \\"unpinned-tor-for-tests\\")]";\n' + bare
                ),
            },
            1,
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
