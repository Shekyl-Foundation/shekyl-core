#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Decide whether a change is documentation only, for the CI scope jobs.

A docs-only change runs the documentation gates and skips the builds, the
test suites and the CodeQL Rust analysis. Every other change runs them all.
The workflows that consume this (build.yml, rust-audit-test.yml,
codeql.yml) skip by a job-level `if:`, never a workflow `paths` filter, so
a required check still reports (as "skipped") and branch protection does
not wait on a context nobody reports.

A changed file is documentation when it is prose, that is `.md` or `.mdc`
anywhere or any file under `docs/`, AND nothing the skipped jobs compile or
run reads it. "Reads it" is computed from the tree, not listed by hand:

- every path-shaped string literal (no whitespace: a message that mentions
  `docs/FOLLOWUPS.md` in a sentence reads nothing; this is safe only because
  no prose path contains whitespace, which the selftest asserts, so the day
  one does the gate fails instead of narrowing silently) in the consumer files
  (below) that contains a `docs/` path names that path, or the directory under it, as an input:
  `include_str!("../../../docs/test_vectors/X.json")`, a runtime
  `join("../../docs/test_vectors")`, a CMake define pointing at a vector;
- a prose file outside `docs/` is an input when a consumer literal resolves
  to it, relative to the consumer's own directory or to its crate's root
  (`CARGO_MANIFEST_DIR`): a crate's `#![doc = include_str!("../README.md")]`
  compiles that crate's README into rustdoc and the doctests, and no other
  README.

Consumers are the files the skipped jobs build or run: everything under
`rust/`, `src/`, `tests/`, `cmake/` and `contrib/`, every `CMakeLists.txt`,
and each `scripts/` file the consuming workflows invoke by path (read from
those workflow files), except this classifier, which reads no document. The
documentation gates' own scripts are not consumers: those gates always run.

A source file is never documentation, however small the edit: a doc-comment
change inside a `.rs` file can break a build or a doctest.

FAILS CLOSED. Any error, an empty file list, or an unreadable tree prints
the reason and answers `docs_only=false`, so everything runs. A wrong
`true` skips the real matrix on a source change; a wrong `false` costs
runner minutes. Only the first can merge broken code.

Usage:
  change_scope.py --base <sha> --head <sha>   # writes docs_only=… to $GITHUB_OUTPUT
  change_scope.py --files a b c               # classify the given paths
  change_scope.py --selftest                  # pinned cases against this tree
"""

import argparse
import os
import re
import subprocess
import sys

PROSE_SUFFIXES = (".md", ".mdc")
SELF = "scripts/ci/change_scope.py"
CONSUMER_DIRS = ("rust/", "src/", "tests/", "cmake/", "contrib/")
CONSUMING_WORKFLOWS = (
    ".github/workflows/build.yml",
    ".github/workflows/rust-audit-test.yml",
    ".github/workflows/codeql.yml",
)
# A string literal: double-quoted, no newline. Escapes are rare in paths and a
# miss here only widens what counts as an input (fail-closed).
LITERAL = re.compile(r'"([^"\n]*)"')
DOCS_IN_LITERAL = re.compile(r'(?:^|[/"\s(])(docs/[^"\n]*)')
WHITESPACE = re.compile(r"\s")
# Where a literal stops being a fixed path: a format placeholder or a glob.
PATH_STOP = re.compile(r'[{}*$%<>?\[\]]')


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def is_prose(path):
    return path.startswith("docs/") or path.endswith(PROSE_SUFFIXES)


def consumer_files():
    tracked = git("ls-files").splitlines()
    scripts = set()
    for wf in CONSUMING_WORKFLOWS:
        try:
            with open(wf, encoding="utf-8") as f:
                scripts.update(re.findall(r"scripts/[A-Za-z0-9_./-]+", f.read()))
        except OSError:
            raise RuntimeError(f"cannot read consuming workflow {wf}")
    out = []
    for p in tracked:
        if is_prose(p):
            continue
        if p == SELF:
            continue
        if p.startswith(CONSUMER_DIRS) or p == "CMakeLists.txt" or p.endswith("/CMakeLists.txt") or p in scripts:
            out.append(p)
    if not out:
        raise RuntimeError("no consumer files found; refusing to classify")
    return out


# A whole-line comment quotes paths in prose ("see `../README.md`") without
# reading them. Dropping those lines keeps a quoted mention from counting as an
# input; a trailing comment on a code line stays, which only widens the set.
# Comment syntax follows the file type: in Rust `#` opens an attribute
# (`#![doc = include_str!(…)]`), never a comment.
C_LIKE = re.compile(r"^\s*(?://|/\*|\*)")
HASH = re.compile(r"^\s*#")
C_LIKE_SUFFIXES = (".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".inl", ".ipp")
HASH_SUFFIXES = (".cmake", ".txt", ".sh", ".py", ".ps1", ".yml", ".yaml", ".toml", ".mk")


def code_text(path):
    if path.endswith(C_LIKE_SUFFIXES):
        comment = C_LIKE
    elif path.endswith(HASH_SUFFIXES) or os.path.basename(path) in ("Makefile", "CMakeLists.txt"):
        comment = HASH
    else:
        return read_text(path)
    return "\n".join(l for l in read_text(path).splitlines() if not comment.match(l))


def crate_root(path):
    """The nearest ancestor holding a Cargo.toml, else the file's directory."""
    d = os.path.dirname(path)
    while d:
        if os.path.isfile(os.path.join(d, "Cargo.toml")):
            return d
        d = os.path.dirname(d)
    return os.path.dirname(path)


def read_text(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return ""
    if b"\0" in raw[:8192]:
        return ""
    return raw.decode("utf-8", errors="replace")


class Inputs:
    """The docs paths and prose file names the consumers read."""

    def __init__(self, consumers):
        self.exact = set()      # a fixed path: the file, or a directory above files
        self.prefixes = set()   # a path cut at a placeholder: a plain prefix
        self.resolved = set()   # prose paths a literal resolves to, outside docs/
        for path in consumers:
            here = os.path.dirname(path)
            root = crate_root(path)
            for lit in LITERAL.findall(code_text(path)):
                if WHITESPACE.search(lit):
                    continue
                if lit.endswith(PROSE_SUFFIXES) and not PATH_STOP.search(lit):
                    rel = lit.lstrip("/")
                    for base in {here, root}:
                        self.resolved.add(os.path.normpath(os.path.join(base, rel)))
                for m in DOCS_IN_LITERAL.finditer(lit):
                    tail = m.group(1)
                    stop = PATH_STOP.search(tail)
                    if stop:
                        self.prefixes.add(tail[: stop.start()])
                    else:
                        self.exact.add(os.path.normpath(tail))

    def reads(self, path):
        if path in self.exact:
            return f"named by a consumer literal"
        for e in self.exact:
            if path.startswith(e + "/"):
                return f"under {e}/, which a consumer reads"
        for p in self.prefixes:
            if path.startswith(p):
                return f"matches the consumer pattern {p}…"
        if path in self.resolved:
            return "a consumer literal resolves to it"
        return None


def classify(files, inputs):
    """Return (docs_only, reasons). A single non-documentation file decides."""
    reasons = []
    for f in files:
        if not is_prose(f):
            reasons.append(f"{f}: not prose")
            return False, reasons
        why = inputs.reads(f)
        if why:
            reasons.append(f"{f}: {why}")
            return False, reasons
    return True, [f"{len(files)} file(s), all prose and read by no consumer"]


def changed_files(base, head):
    if not base or not head:
        raise RuntimeError("no base or head")
    git("cat-file", "-e", f"{base}^{{commit}}")
    files = [f for f in git("diff", "--name-only", base, head).splitlines() if f]
    if not files:
        raise RuntimeError("empty file list")
    return files


def emit(docs_only):
    line = f"docs_only={'true' if docs_only else 'false'}"
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(f"scope: {line}")


SELFTEST = [
    # (path, expected docs_only for a change of that file alone)
    ("docs/design/TOR_SUPERVISOR.md", True),
    ("docs/FOLLOWUPS.md", True),
    (".cursor/rules/00-mission.mdc", True),
    ("CLAUDE.md", True),
    ("docs/design/CRYPTO_DOMAIN_REGISTRY.tsv", False),   # include_str! in a crypto-pq test
    ("docs/test_vectors/PQC_HYBRID_V2_KAT.json", False),  # read at test time
    ("docs/test_vectors/WALLET_FILE_FORMAT_V1/anything", False),  # a directory a test joins
    ("docs/LMDB_WRITE_ATOMICITY_AUDIT.md", False),        # a markdown file a Rust test reads
    ("rust/shekyl-bulletproofs/README.md", False),        # #![doc = include_str!("../README.md")]
    ("rust/shekyl-scanner/README.md", True),              # a README no code reads
    ("tests/README.md", True),
    ("README.md", True),                                  # quoted only in a cmake comment
    ("rust/shekyl-tor/src/lib.rs", False),                # any .rs, doc comment or not
    ("CMakeLists.txt", False),
    ("src/p2p/net_node.inl", False),
    (".github/workflows/build.yml", False),
    ("scripts/ci/change_scope.py", False),
]


def selftest():
    inputs = Inputs(consumer_files())
    bad = 0
    for path, want in SELFTEST:
        got, reasons = classify([path], inputs)
        ok = got == want
        bad += not ok
        print(f"[{'ok' if ok else 'WRONG'}] {path}: docs_only={got} (want {want}) — {reasons[-1]}")
    # Subject assertion (rule 47): the scan found the inputs the cases rely on.
    if "docs/design/CRYPTO_DOMAIN_REGISTRY.tsv" not in inputs.exact:
        print("WRONG: the scan did not find the domain registry's include_str!")
        bad += 1
    # The whitespace exclusion narrows what counts as an input. It is safe
    # only while no prose path contains whitespace; assert that here, so a
    # path with a space fails the gate instead of skipping a build quietly.
    spaced = [p for p in git("ls-files").splitlines() if is_prose(p) and WHITESPACE.search(p)]
    if spaced:
        print(f"WRONG: prose paths contain whitespace, so a read of one would be missed: {spaced[:5]}")
        bad += 1
    # A sentence that mentions a document reads nothing (external/CMakeLists.txt
    # and the staking sim name docs/FOLLOWUPS.md in messages).
    if inputs.reads("docs/FOLLOWUPS.md"):
        print("WRONG: a prose mention of docs/FOLLOWUPS.md counted as a read")
        bad += 1
    # A mixed change is decided by its one code file.
    got, _ = classify(["docs/design/TOR_SUPERVISOR.md", "rust/shekyl-tor/src/lib.rs"], inputs)
    if got:
        print("WRONG: a docs file plus a .rs file was called docs-only")
        bad += 1
    print(f"selftest: {len(SELFTEST) + 4 - bad} of {len(SELFTEST) + 4} hold")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base")
    ap.add_argument("--head")
    ap.add_argument("--files", nargs="+")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    try:
        files = args.files or changed_files(args.base, args.head)
        docs_only, reasons = classify(files, Inputs(consumer_files()))
    except Exception as e:  # fail closed on anything
        print(f"scope: cannot decide ({e}); running everything (fail-closed)")
        emit(False)
        return 0
    for r in reasons:
        print(f"scope: {r}")
    emit(docs_only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
