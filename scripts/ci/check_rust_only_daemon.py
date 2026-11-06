#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
"""The daemon is Rust: no C++ in its link, and no Rust import of our C.

Ruled 2026-11-05 (Rick), the outcome of the p2p remnant cutover
(`P2P_3_REMNANT_CUTOVER_BRIEF.md` §1: `shekyld` links no C++):

1. The built `shekyld` has no C++ runtime among its dynamic dependencies
   (`readelf -d` NEEDED: libstdc++, libc++, libc++abi, libsupc++), and
   none of our C++'s symbols: no mangled `_Z` symbol whose first name is a
   namespace our C++ declares (read from `src/` and `contrib/epee/`). Rust's
   own legacy-mangled symbols also begin `_ZN`; each carries its `17h<16
   hex>E` hash and is not ours.
2. No `extern` block under `rust/` imports a symbol declared under `src/`
   with C linkage: in an `extern "C"` block or declaration of a C++ file,
   or at file scope of a C file or a C header (no `namespace`, `class` or
   `template` in it), `static` excepted.

Each half asserts its subject first (rule 47): the binary is an ELF with
dynamic entries and an unstripped symbol table, the namespace set is not
empty, and the C declarations under `src/` are not empty. ELF only: the
Linux build job runs it on the staged binary.

`--selftest` runs both halves against synthetic inputs, one red case each.

Usage: check_rust_only_daemon.py <path to shekyld> | --selftest
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CXX_RUNTIMES = ("libstdc++", "libc++", "libc++abi", "libsupc++")
RUST_LEGACY_HASH = re.compile(r"17h[0-9a-f]{16}E")
CXX_SOURCES = (".cpp", ".cc", ".cxx", ".hpp", ".inl")
C_SOURCES = (".c",)
HEADERS = (".h",)
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "defined", "alignof", "decltype"}


def strip_c(text):
    """Comments and string literals out of C or C++ source."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


def braced(text, start):
    """The text inside the braces that open at or after `start`."""
    open_at = text.find("{", start)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at + 1 : i]
    return text[open_at + 1 :]


def declared_names(text):
    return {m.group(1) for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text)} - KEYWORDS


def c_linkage(path, raw):
    """Names `path` declares with C linkage."""
    text = strip_c(raw)
    names = set()
    raw_extern_c = 'extern ""'  # an `extern "C"` after strip_c emptied its string
    for m in re.finditer(re.escape(raw_extern_c) + r"\s*\{", text):
        names |= declared_names(braced(text, m.start()))
    for m in re.finditer(re.escape(raw_extern_c) + r"\s+(?!\{)([^;{]*?)\b([A-Za-z_]\w*)\s*\(", text):
        names.add(m.group(2))
    c_file = path.suffix in C_SOURCES or (
        path.suffix in HEADERS and not re.search(r"\b(namespace|class|template)\b", text)
    )
    if c_file:
        for m in re.finditer(r"^(?!static\b|#)[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\(", text, re.M):
            names.add(m.group(1))
    return names - KEYWORDS


def src_c_declarations(root):
    names = {}
    for path in sorted((root / "src").rglob("*")):
        if path.suffix in CXX_SOURCES + C_SOURCES + HEADERS and path.is_file():
            raw = path.read_text(encoding="utf-8", errors="replace")
            for name in c_linkage(path, raw):
                names.setdefault(name, str(path.relative_to(root)))
    return names


def rust_imports(text):
    """Names an `extern "<abi>"` block in Rust source imports."""
    names = set()
    for m in re.finditer(r'\bextern\s+"[A-Za-z0-9_-]+"\s*\{', text):
        body = braced(text, m.start())
        names |= {n.group(1) for n in re.finditer(r"\bfn\s+([A-Za-z_]\w*)", body)}
        names |= {n.group(1) for n in re.finditer(r"\bstatic\s+(?:mut\s+)?([A-Za-z_]\w*)", body)}
    return names


def rust_import_sites(root):
    out = []
    for path in sorted((root / "rust").rglob("*.rs")):
        if "/target/" in str(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r"//[^\n]*", "", text)
        for name in rust_imports(text):
            out.append((str(path.relative_to(root)), name))
    return out


def cxx_namespaces(root):
    names = set()
    for base in (root / "src", root / "contrib" / "epee"):
        for path in base.rglob("*"):
            if path.suffix in CXX_SOURCES + HEADERS and path.is_file():
                text = strip_c(path.read_text(encoding="utf-8", errors="replace"))
                for m in re.finditer(r"\bnamespace\s+([A-Za-z_]\w*)", text):
                    names.add(m.group(1))
    return names - {"std", "detail", "boost"}


def our_cxx_symbol(symbol, namespaces):
    """Whether mangled `symbol` is our C++: a `_Z` name whose first
    component is one of `namespaces`, and not a Rust legacy symbol."""
    if not symbol.startswith("_Z") or RUST_LEGACY_HASH.search(symbol):
        return False
    m = re.match(r"_ZN[KVr]*(\d+)", symbol) or re.match(r"_Z(\d+)", symbol)
    if not m:
        return False
    length = int(m.group(1))
    start = m.end()
    return symbol[start : start + length] in namespaces


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


def check_binary(libs, syms, namespaces):
    errors = []
    if not libs:
        errors.append("the binary has no NEEDED entries: not a dynamic ELF, or readelf failed (rule 47)")
    if syms is None or len(syms) < 1000:
        errors.append("the binary's symbol table is missing or stripped; the C++ symbol check needs it (rule 47)")
    if not namespaces:
        errors.append("no C++ namespace was read from src/ or contrib/epee (rule 47)")
    for lib in libs or []:
        if any(lib.startswith(runtime) for runtime in CXX_RUNTIMES):
            errors.append(f"a C++ runtime is a dynamic dependency: {lib}")
    ours = [s for s in syms or [] if our_cxx_symbol(s, namespaces)]
    if ours:
        listing = "\n".join(f"      {s}" for s in ours[:20])
        errors.append(f"{len(ours)} of our C++'s symbols are in the binary:\n{listing}")
    return errors


def check_imports(sites, declared):
    errors = []
    if not declared:
        errors.append("no C-linkage declaration was read under src/ (rule 47)")
    for path, name in sites:
        if name in declared:
            errors.append(f"{path} imports `{name}`, which {declared[name]} declares: Rust imports no C or C++ of ours")
    return errors


def selftest():
    ns = {"cryptonote", "epee"}
    assert our_cxx_symbol("_ZN10cryptonote5blockC1Ev", ns)
    assert our_cxx_symbol("_ZNK4epee6string3getEv", ns)
    assert not our_cxx_symbol("_ZN10cryptonote3foo17h0123456789abcdefE", ns), "a Rust legacy symbol"
    assert not our_cxx_symbol("_ZNSt6vectorIiE9push_backEv", ns), "std is not ours"
    assert not our_cxx_symbol("_RNvCs1_4core3fmt", ns)
    many = ["x"] * 1000
    assert check_binary(["libc.so.6"], many, ns) == []
    assert check_binary(["libstdc++.so.6", "libc.so.6"], many, ns), "a C++ runtime is red"
    assert check_binary(["libc.so.6"], many + ["_ZN10cryptonote5blockC1Ev"], ns), "our symbol is red"
    assert check_binary(["libc.so.6"], ["x"], ns), "a stripped binary is red"
    header = 'extern "C" {\nint shekyl_probe(int x);\n}\nnamespace a { void b(); }\n'
    assert "shekyl_probe" in c_linkage(pathlib.Path("x.h"), header)
    assert "b" not in c_linkage(pathlib.Path("x.h"), header), "C++ linkage is not C"
    c_src = "static int hidden(void) { return 0; }\nvoid keccak(const char *in);\n"
    assert c_linkage(pathlib.Path("k.c"), c_src) == {"keccak"}
    rust = 'unsafe extern "C" {\n    fn keccak(input: *const u8);\n    static mut x: i32;\n}\nextern "C" fn exported() {}\n'
    assert rust_imports(rust) == {"keccak", "x"}
    declared = {"keccak": "src/crypto/keccak.c"}
    assert check_imports([("rust/a.rs", "clock_gettime")], declared) == []
    assert check_imports([("rust/a.rs", "keccak")], declared), "an import of our C is red"
    print("check_rust_only_daemon selftest: ok")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return 0
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1])
        return 2
    binary = sys.argv[1]
    if not pathlib.Path(binary).is_file():
        print(f"FAIL: no binary at {binary} (rule 47)")
        return 1
    namespaces = cxx_namespaces(ROOT)
    errors = check_binary(needed(binary), symbols(binary), namespaces)
    declared = src_c_declarations(ROOT)
    sites = rust_import_sites(ROOT)
    errors += check_imports(sites, declared)
    if errors:
        print("FAIL: the daemon is not Rust alone:")
        for e in errors:
            print(f"  {e}")
        return 1
    print(
        f"PASS: {binary} needs no C++ runtime and carries none of our C++'s symbols "
        f"({len(namespaces)} namespaces checked); {len(sites)} Rust extern import(s), none "
        f"of the {len(declared)} C-linkage names declared under src/"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
