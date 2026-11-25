#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
"""No first-party C or C++: the end state of the C++ removal.

Ruled 2026-11-06 (Rick): no first-party C or C++ in the tree outside
`external/`, and no first-party build compiling any. Three halves, each
of which asserts its subject before it judges (rule 47):

1. Tracked files (`--tree`). `git ls-files` lists no C or C++ source or
   header outside `external/`. One exemption, and it is structural: a
   patch directory of the depends system, `contrib/depends/patches/<pkg>/`,
   holds patches to a third-party package, and is allowed only while
   `contrib/depends/packages/<pkg>.mk` builds that package. Every submodule
   in `.gitmodules` lives under `external/`. Subject: the listing is not
   empty and holds a gitlink under `external/`.
2. Build scripts (`--tree`). The release is one cargo build per host
   (`cargo xtask`, rust/xtask/matrix.toml), so the only first-party code
   that could compile C is a workspace member's build script. None may:
   a build-dependency on `cc`, `cmake` or `autotools`, or a build script
   that calls a C compiler, make or cmake, or links a native library
   (`rustc-link-lib`), fails. One exemption, `randomx-v2-sys`, which links
   the C RandomX reference for the differential harness and must stay
   outside the shipped graph (`shipped_graph.py`). Subject: build scripts
   were read, and the exempt crate is seen linking C, so the detector is
   shown seeing what it looks for.
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

import pathlib
import re
import subprocess
import sys

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
# A build-dependency that compiles C for its crate.
C_BUILD_DEPS = frozenset({"cc", "cmake", "autotools"})
# A build script that compiles C, runs a C build, or links a native library.
C_BUILD_CALLS = re.compile(
    r"\bcc::Build\b|\bcmake::(?:Config|build)\b|\bautotools::"
    r'|Command::new\(\s*"(?:cc|gcc|clang|cl|c\+\+|g\+\+|clang\+\+|make|cmake)(?:\.exe)?"\s*\)'
    r"|rustc-link-lib="
)
# The one crate whose build script may link C, and why it may.
EXEMPT = {
    "randomx-v2-sys": "links the C RandomX reference for the differential harness "
    "(RANDOMX_V2_RUST.md §2); never in a shipped graph",
}


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


# ── 2. Build scripts ────────────────────────────────────────────────────────


def check_build_scripts(scripts, shipped):
    """`scripts`: crate -> (its build-dependencies, its build script's text
    or None). `shipped`: the crates a release build links."""
    errors = []
    if not scripts:
        errors.append("no workspace member was read (rule 47)")
    for crate, (deps, text) in sorted(scripts.items()):
        code = re.sub(r"//[^\n]*", "", text or "")
        compiles = bool(set(deps) & C_BUILD_DEPS) or bool(C_BUILD_CALLS.search(code))
        if crate in EXEMPT:
            if not compiles:
                errors.append(
                    f"{crate} is exempt but its build script links no C: the detector no "
                    "longer sees it, or the exemption is stale (rule 47)"
                )
            if crate in shipped:
                errors.append(f"{crate} links C and a release build links {crate}")
            continue
        if compiles:
            errors.append(f"{crate}'s build compiles or links C")
    for crate in EXEMPT:
        if crate not in scripts:
            errors.append(f"{crate}, the exempt crate, is not a workspace member (rule 47)")
    return errors


def build_scripts():
    """Every workspace member's build-dependencies and build script."""
    # Here, not at the top: the build job runs --selftest and --binary in an
    # Ubuntu 22.04 container, whose Python 3.10 has no tomllib. --tree runs
    # in the grep gates.
    import tomllib

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from shipped_graph import member_dirs  # noqa: E402

    out = {}
    for crate, path in member_dirs().items():
        manifest = tomllib.loads((path / "Cargo.toml").read_text(encoding="utf-8"))
        deps = set(manifest.get("build-dependencies", {}))
        for table in manifest.get("target", {}).values():
            deps |= set(table.get("build-dependencies", {}))
        build = manifest.get("package", {}).get("build", "build.rs")
        script = path / build if isinstance(build, str) else None
        text = script.read_text(encoding="utf-8") if script and script.is_file() else None
        out[crate] = (deps, text)
    return out


def shipped_set():
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from shipped_graph import live_graphs, shipped_crates  # noqa: E402

    return shipped_crates(live_graphs())


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
    tree = ["rust/a/src/lib.rs", "external/randomx-v2/src/vm.cpp", "README.md"]
    assert check_tracked(tree, links, {"ncurses"}, ["external/randomx-v2"]) == []
    assert check_tracked(tree + ["src/crypto/keccak.c"], links, set(), []), "first-party C is red"
    assert check_tracked(tree + ["tools/x.HPP"], links, set(), []), "the extension check ignores case"
    patch = "contrib/depends/patches/ncurses/fallback.c"
    assert check_tracked(tree + [patch], links, {"ncurses"}, []) == [], "a live package's patch is allowed"
    assert check_tracked(tree + [patch], links, set(), []), "a patch with no package is red"
    assert check_tracked(tree, links, set(), ["vendor/x"]), "a submodule outside external/ is red"
    assert check_tracked([], [], set(), []), "an empty listing is red"
    rx = 'println!("cargo:rustc-link-lib=static=randomx");'
    clean = {"randomx-v2-sys": (set(), rx), "shekyl-types": ({"serde_json"}, "fn main() {}")}
    assert check_build_scripts(clean, {"shekyl-types"}) == []
    planted = dict(clean, **{"shekyl-x": ({"cc"}, 'fn main() { cc::Build::new().file("x.c").compile("x"); }')})
    assert check_build_scripts(planted, set()), "a build script compiling C is red"
    assert check_build_scripts(dict(clean, **{"shekyl-x": ({"cc"}, "fn main() {}")}), set()), "a cc build-dependency is red"
    assert check_build_scripts(dict(clean, **{"shekyl-x": (set(), 'Command::new("gcc")')}), set()), "running gcc is red"
    assert check_build_scripts(clean, {"randomx-v2-sys"}), "the exempt crate in a shipped graph is red"
    assert check_build_scripts(dict(clean, **{"randomx-v2-sys": (set(), "fn main() {}")}), set()), "a stale exemption is red"
    assert check_build_scripts({}, set()), "nothing read is red"
    assert check_build_scripts(dict(clean, **{"shekyl-x": (set(), "// rustc-link-lib= in a comment\nfn main() {}")}), set()) == []
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
        scripts = build_scripts()
        errors += check_build_scripts(scripts, shipped_set())
        with_script = sum(1 for _, text in scripts.values() if text is not None)
        return report(
            errors,
            f"{len(files)} tracked files hold no C or C++ outside {VENDORED}; "
            f"{len(modules)} submodule(s), all under {VENDORED}; "
            f"{with_script} of {len(scripts)} workspace members have a build script, none "
            f"compiling C but {', '.join(EXEMPT)}, outside the shipped graph",
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
