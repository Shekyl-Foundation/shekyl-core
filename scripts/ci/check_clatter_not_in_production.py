#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# clatter is a test-only cross-check and must never enter a production
# dependency graph (docs/design/RPC_CHANNEL.md section 4.1, RT-O12).
#
# WHY A GATE AND NOT A COMMENT. clatter is an independent implementation of
# the Noise pattern the RPC channel adopts. It is in the workspace so that
# vectors can be pinned from it and Shekyl's handshake compared with them. It
# has had no formal audit, and its job is to be a second opinion, not a part.
# The ordinary failure is that someone wants a working handshake and adds the
# dependency that already builds. A sentence in a manifest does not stop that
# (rule 47: a gate asserts its own subject).
#
# WHAT IS CHECKED, in rust/:
#   1. Exactly one manifest names clatter: the cross-check crate's.
#   2. It names it under [dev-dependencies] only, at the exact pinned version,
#      with default features off and without the PQClean feature. clatter's
#      defaults compile a C implementation of ML-KEM; the cross-check needs
#      only the Rust one.
#   3. No manifest names the cross-check crate as a dependency of any kind.
#   4. In Cargo.lock, the only package that lists clatter is the cross-check
#      crate, and no package lists the cross-check crate. The manifests say
#      what was asked for; the lock says what was resolved.
#
# Together: the one edge to clatter is a dev edge of a crate nothing depends
# on, so clatter is in no non-dev graph of any workspace member.
#
# SUBJECT. If clatter is in neither a manifest nor the lock, this gate has
# nothing to check and says so by failing: delete the gate with the crate,
# do not leave it passing over nothing.
#
# Usage:  check_clatter_not_in_production.py            # check the tree
#         check_clatter_not_in_production.py --selftest # bite each failure

import pathlib
import sys
import tempfile
import tomllib

ORACLE = "clatter"
ORACLE_VERSION = "=2.3.0"
XCHECK = "shekyl-rpc-channel-xcheck"
FORBIDDEN_FEATURE = "use-pqclean-ml-kem"
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _tables(manifest):
    """Yield (table_name, table) for every dependency table of a manifest,
    target-specific ones included."""
    for name in DEP_TABLES:
        if isinstance(manifest.get(name), dict):
            yield name, manifest[name]
    for target in (manifest.get("target") or {}).values():
        if isinstance(target, dict):
            for name in DEP_TABLES:
                if isinstance(target.get(name), dict):
                    yield name, target[name]
    workspace = manifest.get("workspace") or {}
    if isinstance(workspace.get("dependencies"), dict):
        yield "workspace.dependencies", workspace["dependencies"]


def _names(table):
    """A table's dependency names, by key and by `package = "..."` rename."""
    for key, spec in table.items():
        yield key, spec
        if isinstance(spec, dict) and isinstance(spec.get("package"), str):
            yield spec["package"], spec


def check(rust_dir):
    problems = []
    rust_dir = pathlib.Path(rust_dir)
    manifests = sorted(p for p in rust_dir.rglob("Cargo.toml") if "target" not in p.parts)
    if not manifests:
        return [f"no Cargo.toml under {rust_dir}: nothing was read"]

    oracle_sites = []
    for path in manifests:
        rel = path.relative_to(rust_dir)
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        package = (manifest.get("package") or {}).get("name")
        for table_name, table in _tables(manifest):
            for name, spec in _names(table):
                if name == XCHECK:
                    problems.append(
                        f"{rel}: [{table_name}] names {XCHECK}. Nothing may depend on the "
                        "cross-check crate; it exists to hold clatter away from everything else.")
                if name != ORACLE:
                    continue
                oracle_sites.append(rel)
                if package != XCHECK:
                    problems.append(
                        f"{rel}: [{table_name}] names {ORACLE}. Only {XCHECK} may, "
                        "and only as a dev-dependency.")
                    continue
                if table_name != "dev-dependencies":
                    problems.append(
                        f"{rel}: {ORACLE} is under [{table_name}]. It must be under "
                        "[dev-dependencies], so it reaches no non-dev graph, this crate's included.")
                if not isinstance(spec, dict):
                    problems.append(
                        f"{rel}: {ORACLE} is declared by version only, which turns its default "
                        "features on. They compile a C ML-KEM; declare default-features = false.")
                    continue
                if spec.get("version") != ORACLE_VERSION:
                    problems.append(
                        f"{rel}: {ORACLE} version is {spec.get('version')!r}, pinned "
                        f"{ORACLE_VERSION!r}. The committed vectors came from that version; "
                        "another is another oracle.")
                if spec.get("default-features") is not False:
                    problems.append(
                        f"{rel}: {ORACLE} must set default-features = false. Its defaults "
                        f"include {FORBIDDEN_FEATURE}, a C build.")
                if FORBIDDEN_FEATURE in (spec.get("features") or []):
                    problems.append(
                        f"{rel}: {ORACLE} enables {FORBIDDEN_FEATURE}, the PQClean C binding.")

    lock_path = rust_dir / "Cargo.lock"
    lock_users = None
    if not lock_path.is_file():
        problems.append(f"{lock_path} is missing: the resolved graph was not read")
    else:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        packages = lock.get("package") or []
        lock_users = set()
        for pkg in packages:
            for dep in pkg.get("dependencies") or []:
                dep_name = dep.split(" ", 1)[0]
                if dep_name == ORACLE:
                    lock_users.add(pkg.get("name"))
                if dep_name == XCHECK:
                    problems.append(
                        f"Cargo.lock: {pkg.get('name')} depends on {XCHECK}.")
        if lock_users - {XCHECK}:
            problems.append(
                "Cargo.lock: " + ", ".join(sorted(lock_users - {XCHECK}))
                + f" depend(s) on {ORACLE}. Only {XCHECK} may.")
        if not any(pkg.get("name") == ORACLE for pkg in packages) and oracle_sites:
            problems.append(
                f"Cargo.lock has no {ORACLE} package though a manifest names it: "
                "the lock is stale, so the resolved graph is unknown.")

    if not oracle_sites and not lock_users:
        problems.append(
            f"{ORACLE} is in no manifest and no lock entry: this gate has no subject. "
            "If the cross-check crate was removed on purpose, remove this gate with it.")
    return problems


# --- self-test ---------------------------------------------------------------

_GOOD_XCHECK = f"""[package]
name = "{XCHECK}"
[dev-dependencies]
{ORACLE} = {{ version = "{ORACLE_VERSION}", default-features = false, features = ["alloc"] }}
"""
_OTHER = """[package]
name = "shekyl-other"
[dependencies]
"""
_GOOD_LOCK = f"""[[package]]
name = "{ORACLE}"
version = "2.3.0"

[[package]]
name = "{XCHECK}"
version = "3.1.0"
dependencies = [
 "{ORACLE}",
]

[[package]]
name = "shekyl-other"
version = "3.1.0"
"""


def _tree(root, xcheck=_GOOD_XCHECK, other=_OTHER, lock=_GOOD_LOCK):
    for name, text in ((XCHECK, xcheck), ("shekyl-other", other)):
        if text is None:
            continue
        (root / name).mkdir(parents=True)
        (root / name / "Cargo.toml").write_text(text, encoding="utf-8")
    if lock is not None:
        (root / "Cargo.lock").write_text(lock, encoding="utf-8")


def selftest():
    cases = [
        ("the intended shape passes", {}, 0),
        ("another crate takes clatter as a dependency",
         {"other": _OTHER + f'{ORACLE} = "2.3.0"\n'}, 1),
        ("the cross-check crate takes clatter as a normal dependency",
         {"xcheck": _GOOD_XCHECK.replace("[dev-dependencies]", "[dependencies]")}, 1),
        ("default features left on",
         {"xcheck": _GOOD_XCHECK.replace("default-features = false, ", "")}, 1),
        ("declared by version only",
         {"xcheck": f'[package]\nname = "{XCHECK}"\n[dev-dependencies]\n{ORACLE} = "{ORACLE_VERSION}"\n'}, 1),
        ("the PQClean feature enabled",
         {"xcheck": _GOOD_XCHECK.replace('["alloc"]', f'["alloc", "{FORBIDDEN_FEATURE}"]')}, 1),
        ("a different clatter version",
         {"xcheck": _GOOD_XCHECK.replace(ORACLE_VERSION, "2.3")}, 1),
        ("a crate depends on the cross-check crate",
         {"other": _OTHER + f'{XCHECK} = {{ path = "../{XCHECK}" }}\n'}, 1),
        ("clatter under a renamed key in another crate",
         {"other": _OTHER + f'noise = {{ package = "{ORACLE}", version = "2.3.0" }}\n'}, 1),
        ("clatter under a target-specific table of another crate",
         {"other": _OTHER + f'[target."cfg(unix)".dependencies]\n{ORACLE} = "2.3.0"\n'}, 1),
        ("the lock shows another package using clatter",
         {"lock": _GOOD_LOCK.replace('name = "shekyl-other"\nversion = "3.1.0"\n',
                                     f'name = "shekyl-other"\nversion = "3.1.0"\ndependencies = [\n "{ORACLE}",\n]\n')}, 1),
        ("the lock shows a package using the cross-check crate",
         {"lock": _GOOD_LOCK.replace('name = "shekyl-other"\nversion = "3.1.0"\n',
                                     f'name = "shekyl-other"\nversion = "3.1.0"\ndependencies = [\n "{XCHECK}",\n]\n')}, 1),
        ("no lock file", {"lock": None}, 1),
        ("clatter gone from everything: no subject",
         {"xcheck": f'[package]\nname = "{XCHECK}"\n',
          "lock": f'[[package]]\nname = "{XCHECK}"\nversion = "3.1.0"\n'}, 1),
    ]
    failed = 0
    for label, overrides, want in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _tree(root, **overrides)
            got = 1 if check(root) else 0
        if got == want:
            print(f"ok   {label}")
        else:
            failed += 1
            print(f"FAIL {label}: wanted {'a refusal' if want else 'a pass'}", file=sys.stderr)
    print(f"{failed} failing case(s)")
    return 1 if failed else 0


def main():
    if "--selftest" in sys.argv[1:]:
        return selftest()
    rust_dir = pathlib.Path(__file__).resolve().parents[2] / "rust"
    problems = check(rust_dir)
    if problems:
        print("clatter production-graph gate: FAIL", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1
    print(f"clatter production-graph gate: PASS ({ORACLE} is a dev-dependency of "
          f"{XCHECK} only, and nothing depends on {XCHECK})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
