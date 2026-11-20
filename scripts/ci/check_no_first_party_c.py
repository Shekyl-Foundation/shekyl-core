#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
"""No first-party C or C++: the end state of the C++ removal.

Ruled 2026-11-06 (Rick): no first-party C or C++ in the tree outside
`external/`, and no CMake target compiling any. Three halves, each of
which asserts its subject before it judges (rule 47):

1. Tracked files (`--tree`). `git ls-files` lists no C or C++ source or
   header outside `external/`. One exemption, and it is structural: a
   patch directory of the depends system, `contrib/depends/patches/<pkg>/`,
   holds patches to a third-party package, and is allowed only while
   `contrib/depends/packages/<pkg>.mk` builds that package. Every submodule
   in `.gitmodules` lives under `external/`. Subject: the listing is not
   empty and holds a gitlink under `external/`.
2. CMake (`--tree`). Configures the tree into a temporary directory with a
   File API codemodel query and reads every target's sources: a source in
   a compile group (one CMake compiles) that is not under `external/`
   fails. Subject: the reply lists `shekyl_rust_bins`, the target that
   builds the binaries. Default options; the RandomX options add only
   ExternalProject custom targets, and a compiled source would show here.
3. The linked daemon (`--binary <shekyld>`). No C++ runtime among its
   dynamic dependencies (`readelf -d` NEEDED: libstdc++, libc++, libc++abi,
   libsupc++), and no C++ symbol: every `_Z` symbol is Rust's
   legacy-mangled form, which carries a `17h<16 hex>E` hash (LLVM may
   append a suffix such as `.llvm.<n>` after it). Subject: an
   ELF with dynamic entries and an unstripped symbol table. ELF only: the
   Linux build job runs it on the staged binary.

`--selftest` runs each half on synthetic inputs, with a red case for each.

Usage: check_no_first_party_c.py --tree | --binary <path to shekyld> | --selftest
"""

import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
C_FAMILY = (
    ".c", ".cc", ".cpp", ".cxx", ".c++",
    ".h", ".hh", ".hpp", ".hxx", ".h++",
    ".inl", ".ipp", ".tcc", ".m", ".mm",
)
VENDORED = "external/"
DEPENDS_PATCHES = re.compile(r"^contrib/depends/patches/([^/]+)/")
CXX_RUNTIMES = ("libstdc++", "libc++", "libc++abi", "libsupc++")
RUST_LEGACY_HASH = re.compile(r"17h[0-9a-f]{16}E")
BINARIES_TARGET = "shekyl_rust_bins"


# ── 1. Tracked files ────────────────────────────────────────────────────────


def check_tracked(files, gitlinks, depends_packages, submodule_paths):
    errors = []
    if not files:
        errors.append("git ls-files listed nothing (rule 47)")
    if not any(link.startswith(VENDORED) for link in gitlinks):
        errors.append(f"no gitlink under {VENDORED}: the listing is not this tree's (rule 47)")
    for path in files:
        if not path.lower().endswith(C_FAMILY) or path.startswith(VENDORED):
            continue
        m = DEPENDS_PATCHES.match(path)
        if m and m.group(1) in depends_packages:
            continue
        errors.append(f"first-party C or C++ is tracked: {path}")
    for path in submodule_paths:
        if not path.startswith(VENDORED):
            errors.append(f"a submodule outside {VENDORED}: {path}")
    return errors


def tracked_inputs(root):
    listing = subprocess.run(
        ["git", "ls-files", "-s"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    files, gitlinks = [], []
    for line in listing:
        meta, path = line.split("\t", 1)
        (gitlinks if meta.startswith("160000") else files).append(path)
    packages = {p.stem for p in (root / "contrib/depends/packages").glob("*.mk")}
    modules = root / ".gitmodules"
    paths = []
    if modules.is_file():
        paths = re.findall(r"^\s*path\s*=\s*(\S+)", modules.read_text(), flags=re.M)
    return files, gitlinks, packages, paths


# ── 2. CMake ────────────────────────────────────────────────────────────────


def check_codemodel(targets):
    """`targets`: (name, [(source path relative to the tree, compiled?)])."""
    errors = []
    if BINARIES_TARGET not in {name for name, _ in targets}:
        errors.append(f"the codemodel lists no {BINARIES_TARGET} target (rule 47)")
    for name, sources in targets:
        for path, compiled in sources:
            if compiled and not path.startswith(VENDORED):
                errors.append(f"CMake target {name} compiles {path}")
    return errors


def codemodel_targets(root):
    cmake = shutil.which("cmake")
    if cmake is None:
        return None, "cmake is not on PATH; the CMake half cannot run (rule 47)"
    with tempfile.TemporaryDirectory() as build:
        query = pathlib.Path(build, ".cmake/api/v1/query")
        query.mkdir(parents=True)
        (query / "codemodel-v2").touch()
        run = subprocess.run(
            [cmake, "-S", str(root), "-B", build, "-DCMAKE_BUILD_TYPE=Release"],
            capture_output=True, text=True, check=False,
        )
        if run.returncode != 0:
            return None, f"cmake configure exited {run.returncode}:\n{run.stdout}{run.stderr}"
        reply = pathlib.Path(build, ".cmake/api/v1/reply")
        index = sorted(reply.glob("index-*.json"))
        if not index:
            return None, "cmake wrote no File API reply (rule 47)"
        objects = json.loads(index[-1].read_text())["objects"]
        model_file = next((o["jsonFile"] for o in objects if o["kind"] == "codemodel"), None)
        if model_file is None:
            return None, "the File API reply has no codemodel (rule 47)"
        model = json.loads((reply / model_file).read_text())
        source_dir = pathlib.Path(model["paths"]["source"]).resolve()
        targets = []
        for config in model["configurations"]:
            for ref in config["targets"]:
                target = json.loads((reply / ref["jsonFile"]).read_text())
                sources = []
                for src in target.get("sources", []):
                    path = pathlib.Path(src["path"])
                    if not path.is_absolute():
                        path = source_dir / path
                    try:
                        rel = path.resolve().relative_to(source_dir).as_posix()
                    except ValueError:
                        rel = path.as_posix()
                    sources.append((rel, "compileGroupIndex" in src))
                targets.append((target["name"], sources))
        return targets, None


# ── 3. The linked daemon ────────────────────────────────────────────────────


def cxx_symbol(symbol):
    """A C++-mangled symbol that is not Rust's legacy mangling."""
    return symbol.startswith("_Z") and not RUST_LEGACY_HASH.search(symbol)


def needed(binary):
    out = subprocess.run(["readelf", "-d", binary], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        return None
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", out.stdout)


def symbols(binary):
    out = subprocess.run(["nm", binary], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        return None
    return [line.split()[-1] for line in out.stdout.splitlines() if line.split()]


def check_binary(libs, syms):
    errors = []
    if not libs:
        errors.append("the binary has no NEEDED entries: not a dynamic ELF, or readelf failed (rule 47)")
    if syms is None or len(syms) < 1000:
        errors.append("the binary's symbol table is missing or stripped; the C++ symbol check needs it (rule 47)")
    for lib in libs or []:
        if any(lib.startswith(runtime) for runtime in CXX_RUNTIMES):
            errors.append(f"a C++ runtime is a dynamic dependency: {lib}")
    cxx = [s for s in syms or [] if cxx_symbol(s)]
    if cxx:
        listing = "\n".join(f"      {s}" for s in cxx[:20])
        errors.append(f"{len(cxx)} C++ symbol(s) are in the binary:\n{listing}")
    return errors


# ── Selftest and entry ──────────────────────────────────────────────────────


def selftest():
    links = ["external/randomx-v2"]
    tree = ["rust/a/src/lib.rs", "external/randomx-v2/src/vm.cpp", "CMakeLists.txt"]
    assert check_tracked(tree, links, {"ncurses"}, ["external/randomx-v2"]) == []
    assert check_tracked(tree + ["src/crypto/keccak.c"], links, set(), []), "first-party C is red"
    assert check_tracked(tree + ["tools/x.HPP"], links, set(), []), "the extension check ignores case"
    patch = "contrib/depends/patches/ncurses/fallback.c"
    assert check_tracked(tree + [patch], links, {"ncurses"}, []) == [], "a live package's patch is allowed"
    assert check_tracked(tree + [patch], links, set(), []), "a patch with no package is red"
    assert check_tracked(tree, links, set(), ["vendor/x"]), "a submodule outside external/ is red"
    assert check_tracked([], [], set(), []), "an empty listing is red"
    bins = (BINARIES_TARGET, [])
    assert check_codemodel([bins, ("randomx_v2_external", [("external/randomx-v2/x.cpp", False)])]) == []
    assert check_codemodel([bins, ("probe", [("tools/probe.c", True)])]), "a compiled first-party source is red"
    assert check_codemodel([bins, ("rx", [("external/randomx-v2/vm.cpp", True)])]) == []
    assert check_codemodel([("other", [])]), "no binaries target is red"
    many = ["x"] * 1000
    assert not cxx_symbol("_ZN4core3fmt5write17h0123456789abcdefE"), "a Rust legacy symbol"
    assert not cxx_symbol("_ZN4core3fmt5write17h0123456789abcdefE.llvm.123"), "with an LLVM suffix"
    assert cxx_symbol("_ZNSt6vectorIiE9push_backEv")
    assert cxx_symbol("_ZN10cryptonote5blockC1Ev")
    assert not cxx_symbol("_RNvCs1_4core3fmt")
    assert check_binary(["libc.so.6"], many) == []
    assert check_binary(["libstdc++.so.6", "libc.so.6"], many), "a C++ runtime is red"
    assert check_binary(["libc.so.6"], many + ["_ZN10cryptonote5blockC1Ev"]), "a C++ symbol is red"
    assert check_binary(["libc.so.6"], ["x"]), "a stripped binary is red"
    print("check_no_first_party_c selftest: ok")


def report(errors, passed):
    if errors:
        print("FAIL: first-party C or C++ is present:")
        for e in errors:
            print(f"  {e}")
        return 1
    print(f"PASS: {passed}")
    return 0


def main():
    args = sys.argv[1:]
    if args == ["--selftest"]:
        selftest()
        return 0
    if args == ["--tree"]:
        files, gitlinks, packages, modules = tracked_inputs(ROOT)
        errors = check_tracked(files, gitlinks, packages, modules)
        targets, failure = codemodel_targets(ROOT)
        if failure:
            errors.append(failure)
        else:
            errors += check_codemodel(targets)
        compiled = 0 if targets is None else sum(c for _, s in targets for _, c in s)
        return report(
            errors,
            f"{len(files)} tracked files hold no C or C++ outside {VENDORED}; "
            f"{len(modules)} submodule(s), all under {VENDORED}; "
            f"CMake configures {len(targets or [])} target(s), compiling {compiled} source(s)",
        )
    if len(args) == 2 and args[0] == "--binary":
        binary = args[1]
        if not pathlib.Path(binary).is_file():
            print(f"FAIL: no binary at {binary} (rule 47)")
            return 1
        libs, syms = needed(binary), symbols(binary)
        return report(
            check_binary(libs, syms),
            f"{binary} needs no C++ runtime and holds no C++ symbol ({len(syms or [])} symbols read)",
        )
    print(__doc__.strip().splitlines()[-1])
    return 2


if __name__ == "__main__":
    sys.exit(main())
