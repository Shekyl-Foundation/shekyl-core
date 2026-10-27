#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The other direction of the FFI signature gate: C++ exports that Rust imports.

`check_ffi_signatures.sh` compares Rust exports against the hand-written
header C++ reads. Nothing compared the reverse: a function C++ defines and
Rust declares in an `extern "C"` block. Such a declaration is checked by no
compiler on either side — Rust trusts its own `extern` block, C++ never sees
it — so a parameter added to one side alone links and runs, and the call
reads garbage for the argument the other side never sent. The posture
parameter of `core_rpc_ffi_json_endpoint` (DAEMON_CONFIG_CUTOVER.md §2.3's
one RPC start) is a `bool` of exactly that shape.

For every function a gated Rust file imports, this finds the one C
declaration of it under `src/` and compares arity, each parameter's type
class and the return type's class. A class, not a spelling: `uint64_t` and
`u64` are the same class, `const char*` and `*const c_char` are both
pointers. A pointer's pointee is not compared (an opaque handle redeclares
as any pointer type); a pointer passed where an integer is declared is.

Functions Rust itself exports (`extern "C" fn` in any Rust source) are
skipped here: those are the forward gate's operands, and a Rust import of a
Rust export is one crate reading another's ABI, which the forward gate's
header already pins.

Exit 0 when every import agrees; 1 naming each disagreement; 2 on a
pattern that found nothing (rule 47: a gate asserts its own subject).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

# The Rust files whose `extern "C"` blocks import C++ functions.
GATED_RUST = [
    "rust/shekyl-daemon-rpc/src/ffi.rs",
]

# Where the C declarations live. The hand-written Rust-export header is not
# a declaration site for this direction.
C_HEADER_ROOT = "src"
C_HEADER_EXCLUDE = {"src/shekyl/shekyl_ffi.h"}

RUST_INT = {
    "i8": "int8",
    "u8": "int8",
    "i16": "int16",
    "u16": "int16",
    "i32": "int32",
    "u32": "int32",
    "c_int": "int32",
    "c_uint": "int32",
    "i64": "int64",
    "u64": "int64",
    "isize": "size",
    "usize": "size",
    "f32": "f32",
    "f64": "f64",
    "bool": "bool",
}

C_SCALAR = {
    "int8_t": "int8",
    "uint8_t": "int8",
    "char": "int8",
    "unsigned char": "int8",
    "signed char": "int8",
    "int16_t": "int16",
    "uint16_t": "int16",
    "short": "int16",
    "unsigned short": "int16",
    "int32_t": "int32",
    "uint32_t": "int32",
    "int": "int32",
    "unsigned": "int32",
    "unsigned int": "int32",
    "std::int32_t": "int32",
    "std::uint32_t": "int32",
    "int64_t": "int64",
    "uint64_t": "int64",
    "std::int64_t": "int64",
    "std::uint64_t": "int64",
    "size_t": "size",
    "ssize_t": "size",
    "std::size_t": "size",
    "float": "f32",
    "double": "f64",
    "bool": "bool",
    "void": "void",
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def split_top(text: str) -> list[str]:
    """Split on commas outside brackets."""
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return [p.strip() for p in out if p.strip()]


def rust_class(ty: str) -> str:
    ty = ty.strip()
    if ty.startswith("*"):
        return "ptr"
    leaf = ty.rsplit("::", 1)[-1]
    if leaf in RUST_INT:
        return RUST_INT[leaf]
    return f"other:{ty}"


def c_class(ty: str) -> str:
    ty = ty.strip()
    if "*" in ty or "[" in ty:
        return "ptr"
    words = [w for w in ty.split() if w not in ("const", "volatile")]
    joined = " ".join(words)
    if joined in C_SCALAR:
        return C_SCALAR[joined]
    return f"other:{joined}"


def rust_imports(text: str) -> dict[str, tuple[list[str], str]]:
    """Every `fn` inside an `extern "C" { ... }` block: name -> (param classes, return class)."""
    text = strip_comments(text)
    found: dict[str, tuple[list[str], str]] = {}
    for m in re.finditer(r'extern\s+"C"\s*\{', text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        block = text[m.end() : i - 1]
        for fm in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*(?:->\s*([^;]+))?;", block, flags=re.S):
            name, params, ret = fm.group(1), fm.group(2), fm.group(3)
            classes = []
            for p in split_top(params):
                if ":" not in p:
                    classes.append(f"other:{p}")
                    continue
                classes.append(rust_class(p.split(":", 1)[1]))
            found[name] = (classes, rust_class(ret) if ret else "void")
    return found


def c_declarations(root: Path, exclude: set[str]) -> dict[str, list[tuple[str, list[str], str]]]:
    """name -> [(file, param classes, return class)] over every header under root."""
    decls: dict[str, list[tuple[str, list[str], str]]] = {}
    for path in sorted(root.rglob("*.h")):
        rel = path.relative_to(root.parent).as_posix()
        if rel in exclude or rel.startswith("build"):
            continue
        text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        text = re.sub(r"^\s*#.*$", " ", text, flags=re.M)
        for dm in re.finditer(
            r"(?<![\w.>])([A-Za-z_][\w:]*(?:\s*\*+|\s+[A-Za-z_][\w:]*\s*\*+|\s+[A-Za-z_][\w:]*)*)\s+\*?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*;",
            text,
            flags=re.S,
        ):
            ret, name, params = dm.group(1), dm.group(2), dm.group(3)
            ret_text = ret.strip()
            if ret_text.split()[0] in ("return", "typedef", "using", "else", "extern", "static"):
                ret_text = " ".join(ret_text.split()[1:])
            if not ret_text:
                continue
            # The parameter list's whole text decided the return pointer above:
            # a `char* name(` match leaves the `*` in `ret` or before the name.
            if dm.group(0).lstrip().startswith(ret_text) and "*" in dm.group(0)[len(ret_text) : dm.group(0).index(name)]:
                ret_text += "*"
            pclasses: list[str] = []
            plist = params.strip()
            if plist and plist != "void":
                for p in split_top(plist):
                    p = p.strip()
                    if p == "...":
                        pclasses.append("variadic")
                        continue
                    # Drop a trailing identifier (the parameter's name) when
                    # the text has one; `const char*` alone has none.
                    tokens = re.findall(r"[A-Za-z_][\w:]*|\*|\[\]", p)
                    if len(tokens) >= 2 and re.fullmatch(r"[A-Za-z_][\w]*", tokens[-1]) and tokens[-1] not in C_SCALAR and tokens[-1] not in ("const", "volatile", "unsigned", "signed", "int", "char", "short"):
                        tokens = tokens[:-1]
                    pclasses.append(c_class(" ".join(tokens)))
            decls.setdefault(name, []).append((rel, pclasses, c_class(ret_text)))
    return decls


def rust_exports(root: Path) -> set[str]:
    names: set[str] = set()
    for path in root.rglob("*.rs"):
        if "/target/" in path.as_posix():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        # A test module's link stubs define the C++ exports under
        # `#[cfg(test)]` so unit tests link without C++; they are not
        # exports of the shipped crate. Test modules are the last items of
        # a file (clippy's items-after-test-module), so the cut is the
        # first attribute.
        text = text.split("#[cfg(test)]", 1)[0]
        for m in re.finditer(r'extern\s+"C"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)', text):
            names.add(m.group(1))
    return names


CHECKED: list[str] = []


def check(repo: Path, gated: list[str], header_root: str, exclude: set[str]) -> list[str]:
    errors: list[str] = []
    CHECKED.clear()
    exports = rust_exports(repo / "rust")
    decls = c_declarations(repo / header_root, exclude)
    checked = 0
    for rel in gated:
        imports = rust_imports((repo / rel).read_text(encoding="utf-8"))
        if not imports:
            errors.append(f"{rel}: no extern \"C\" import found — the pattern is wrong or the surface moved")
            continue
        for name, (pclasses, rclass) in sorted(imports.items()):
            if name in exports:
                continue
            sites = decls.get(name, [])
            if not sites:
                errors.append(f"{rel}: {name} is imported but no header under {header_root}/ declares it")
                continue
            if len({(tuple(p), r) for _, p, r in sites}) > 1:
                errors.append(f"{rel}: {name} is declared with differing signatures in " + ", ".join(s[0] for s in sites))
                continue
            cfile, cparams, cret = sites[0]
            if len(cparams) != len(pclasses):
                errors.append(
                    f"{rel}: {name} takes {len(pclasses)} parameter(s) in Rust and {len(cparams)} in {cfile}"
                )
                continue
            for i, (rc, cc) in enumerate(zip(pclasses, cparams)):
                if rc != cc:
                    errors.append(f"{rel}: {name} parameter {i + 1} is {rc} in Rust and {cc} in {cfile}")
            if rclass != cret:
                errors.append(f"{rel}: {name} returns {rclass} in Rust and {cret} in {cfile}")
            checked += 1
            CHECKED.append(name)
    if checked == 0 and not errors:
        errors.append("no imported C++ function was checked — every import matched a Rust export, or the gated list is empty")
    return errors


def selftest() -> int:
    rust = '''
extern "C" {
    pub fn probe_create(p: *mut std::ffi::c_void) -> *mut Handle;
    pub fn probe_call(h: *mut Handle, uri: *const c_char, body: *const c_char, restricted: bool) -> *mut c_char;
    pub fn probe_count(h: *mut Handle, out: *mut u64) -> i32;
    pub fn probe_free(h: *mut Handle);
}
'''
    header_ok = '''
#pragma once
typedef struct probe_handle probe_handle;
probe_handle* probe_create(void* p);
// JSON: ...
char* probe_call(probe_handle* h,
    const char* uri, const char* body, bool restricted);
int probe_count(probe_handle* h, uint64_t* out);
void probe_free(probe_handle* h);
'''
    cases = [
        ("agreeing declarations pass", header_ok, []),
        (
            "a parameter present on one side only is named",
            header_ok.replace(", bool restricted", ""),
            ["probe_call takes 4 parameter(s) in Rust and 3"],
        ),
        (
            "a pointer declared where an integer is imported is named",
            header_ok.replace("int probe_count", "int* probe_count"),
            ["probe_count returns int32 in Rust and ptr"],
        ),
        (
            "an integer declared where a pointer is imported is named",
            header_ok.replace("uint64_t* out", "uint64_t out"),
            ["probe_count parameter 2 is ptr in Rust and int64"],
        ),
        (
            "a missing declaration is named",
            header_ok.replace("void probe_free(probe_handle* h);", ""),
            ["probe_free is imported but no header"],
        ),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "rust" / "x" / "src").mkdir(parents=True)
        (repo / "rust" / "x" / "src" / "ffi.rs").write_text(rust)
        (repo / "src" / "p").mkdir(parents=True)
        for title, header, expect in cases:
            (repo / "src" / "p" / "probe.h").write_text(header)
            errors = check(repo, ["rust/x/src/ffi.rs"], "src", set())
            ok = (not errors) if not expect else all(any(e in err for err in errors) for e in expect) and len(errors) == len(expect)
            print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {errors}"))
            failures += 0 if ok else 1
        # A test-module link stub of the same name must not hide the import.
        (repo / "src" / "p" / "probe.h").write_text(header_ok.replace(", bool restricted", ""))
        (repo / "rust" / "x" / "src" / "ffi.rs").write_text(
            rust + '\n#[cfg(test)]\nmod stubs {\n    #[no_mangle]\n    pub extern "C" fn probe_call() {}\n}\n'
        )
        errors = check(repo, ["rust/x/src/ffi.rs"], "src", set())
        ok = any("probe_call takes 4 parameter(s)" in e for e in errors)
        print(f"{'ok' if ok else 'FAIL'}: a cfg(test) link stub does not hide an import" + ("" if ok else f" — got {errors}"))
        failures += 0 if ok else 1
        (repo / "rust" / "x" / "src" / "ffi.rs").write_text(rust)
        # The subject assertion: an empty gated list is a failure, not a pass.
        errors = check(repo, [], "src", set())
        ok = bool(errors)
        print(f"{'ok' if ok else 'FAIL'}: an empty gated list is refused")
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    repo = Path(__file__).resolve().parents[2]
    os.chdir(repo)
    errors = check(repo, GATED_RUST, C_HEADER_ROOT, C_HEADER_EXCLUDE)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2 if any("pattern is wrong" in e or "no imported" in e for e in errors) else 1
    imports = sum(len(rust_imports((repo / r).read_text())) for r in GATED_RUST)
    if "--list" in argv:
        print("\n".join(CHECKED))
    print(
        f"C++ import signatures: every imported C++ function agrees with its header "
        f"({len(CHECKED)} checked, {imports - len(CHECKED)} skipped as Rust exports, over {len(GATED_RUST)} file(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
