#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Decide whether a change is documentation only, for the CI scope jobs.

A docs-only change runs the documentation gates and skips the builds, the
test suites and the CodeQL Rust analysis. Every other change runs them,
each as far as its own scope below says. The workflows that consume this
(build.yml, rust-audit-test.yml, codeql.yml) skip by a job-level `if:`,
never a workflow `paths` filter, so a required check still reports (as
"skipped") and branch protection does not wait on a context nobody
reports.

A changed file is documentation when it is prose, that is `.md` or `.mdc`
anywhere or any other file under `docs/` outside a consumer tree (below),
AND nothing the skipped jobs compile or run reads it. "Reads it" is computed from the tree, not listed by hand:

- every path-shaped string literal (no whitespace: a message that mentions
  `docs/FOLLOWUPS.md` in a sentence reads nothing; this is safe only because
  no prose path contains whitespace, which the selftest asserts, so the day
  one does the gate fails instead of narrowing silently) in the consumer files
  (below) that contains a `docs/` path names that path, or the directory under it, as an input:
  `include_str!("../../../docs/test_vectors/X.json")`, a runtime
  `join("../../docs/test_vectors")`;
- a prose file outside `docs/` is an input when a consumer literal resolves
  to it, relative to the consumer's own directory or to its crate's root
  (`CARGO_MANIFEST_DIR`): a crate's `#![doc = include_str!("../README.md")]`
  compiles that crate's README into rustdoc and the doctests, and no other
  README;
- a relative literal (`../results`) in a consumer that lives under `docs/`
  names the path it resolves to, against the same two bases, when that
  path is under `docs/`: the constant-time harness's tests read the
  records beside the crate.

Consumers are the files the skipped jobs build or run: everything under
`rust/`, `src/`, `tests/` and `contrib/`,
each `scripts/` file the consuming workflows invoke by path, and every
non-prose file of a consumer tree under `docs/`, a directory a consuming
workflow builds in (a step's `working-directory:` there); both read from
those workflow files. This classifier is not a consumer: it reads no
document. The
documentation gates' own scripts are not consumers: those gates always run.

A source file is never documentation, however small the edit: a doc-comment
change inside a `.rs` file can break a build or a doctest.

FAILS CLOSED. Any error, an empty file list, or an unreadable tree prints
the reason and answers `docs_only=false`, so everything runs. A wrong
`true` skips the real matrix on a source change; a wrong `false` costs
runner minutes. Only the first can merge broken code.

Beside `docs_only`, the Rust job's scope (`rust-audit-test.yml`), decided by
dependency, not by topic:

- `rust_job`: `run` or `skip`. The job runs when a changed file is a crate
  or a crate's input, or when a changed script or action belongs to the job
  (`scripts/ci/job_owners.tsv`). A change owned by other jobs only, such as
  a documentation gate, skips it.
- `rust_tests`: `all`, `none`, or the changed workspace packages. The job
  runs every test of the named packages and of every package that depends
  on them, through nextest's `rdeps()`, so a changed fixture or helper runs
  its consumers' tests too: a change to `shekyl-economics` runs the
  economics sim's tests, which pin the shipped constants, and a change to
  the sim alone runs the sim. A file's readers count beside its owner: a
  crate whose test reads a workflow file or a script (the same literal scan,
  over `.github/` and `scripts/` paths too), or that compiles another
  crate's file through `#[path = "…"]`, which cargo has no edge for, is in
  scope when that file changes. A fuzz crate's file (`rust/<crate>/fuzz/`)
  is no package's: the fuzz workflows build the harness, and its manifest
  and lockfile run this job for the crypto closure step, which reads every
  fuzz lock, with no test (ruled 2026-11-22; a lockfile regeneration ran the
  fuzzed crate's whole reverse closure and every OS build). `none` is a job
  that runs for its own gate steps (a changed script it executes) with no
  test to run. `all` is for an
  input every crate shares: the workspace manifest and lock, the toolchain,
  the cargo and nextest configuration, `config/` (read by build scripts), the
  job's own workflow file, this classifier and its ownership table, any path
  nothing claims, and any error (fail-closed, as above).
- `rust_doc_pkgs`: the `-p` arguments for the doctest run, the reverse
  closure of `rust_tests` cut to packages with a library target, since
  `cargo test --doc` refuses a package without one.
- `sim_narrations`: `run` or `skip`, for the economics sim's narration pins
  (`rust-audit-test.yml`'s economics-sim-narrations job). The pins are
  `#[ignore]`d, so `rust_tests` reaching the sim does not run them. They run
  when a changed file is one of what a narration is made of (ruled
  2026-11-16): the consensus configuration the sim and the economics crate
  read, the economics crates, the block-weight rule, and the sim with its
  pin list (`SIM_NARRATION_INPUTS`). #1323 changed the surge factor in
  `config/` and `block_weight.rs` and merged green while the narrations
  moved; both are inputs. A change that reaches the sim only through a
  shared input (the lockfile, the toolchain, the Rust job's workflow) does
  not run them; the nightly lane does.

- `build_jobs`: `run` or `skip`, for build.yml's OS builds (`BUILD_JOBS`,
  the jobs its `work` output gates). They compile every crate through
  `cargo xtask`, so the Rust job's own placement decides it with their jobs and
  workflow in place of the Rust job's: they run when a change reaches a
  package, is an input every crate shares or one nothing claims, is
  build.yml, or is a script or action one of them runs. A change owned by
  other jobs only (another workflow, a merge-ready or documentation script)
  skips them: about 100 runner-minutes on every push of such a pull
  request (ruled 2026-11-22). A missing value runs them.

- `bench_rows`: `all`, `none`, or the benchmark rows a pull request's
  capture runs (`benchmarks.yml`), each `<crate>::<gungraun-target>`. A row
  is a `[[gated_row]]` of the measurement ledger with a path set, the code
  whose change can move its counts. A row runs when the change's reverse
  closure holds a package one of its path set's paths lies in, or when a
  changed file lies under one of those paths. The closure is the
  `rust_tests` packages and everything that links them: without the
  dev-dependency edges, which join nearly every member to nearly every
  other and do not change what a row counts. `all` wherever `rust_tests` is `all`,
  and for a change to the capture's own inputs: `scripts/bench/`, the
  benchmark workflow and the ledger. A wallet change runs the wallet rows
  and not the block path's; the push to `dev` captures every row whatever
  this says.

A pull request is scoped from its merge commit's first parent, the `dev`
the commit under test was built on (`--pr-base`). The event's
`pull_request.base.sha` can be an older or a newer `dev`, and its diff then
counts what `dev` gained in between as the pull request's own: docs-only
#1528 read 64 files and ran every suite.

The ownership table is the truth for `scripts/ci/**` and `.github/**`
outside the workflow files, which own the jobs they define; the selftest
holds the table to the tree (every tracked path claimed, no missing path or
job, a job whose steps name a script is among its owners). Outside those
two directories a row whose path ends in `/` claims a whole directory
(`contrib/depends/`, the depends jobs' tree): a file under it is the named
jobs' and no crate's, unless a crate reads it.

Usage:
  change_scope.py --base <sha> --head <sha>   # writes docs_only=…, build_jobs=…,
                                              # rust_job=…, rust_tests=…,
                                              # rust_doc_pkgs=…,
                                              # bench_rows=…
                                              # to $GITHUB_OUTPUT
  change_scope.py --files a b c               # classify the given paths
  change_scope.py --pr-base MERGE PR_HEAD     # prints the `dev` a pull request's
                                              # merge commit was built on, its
                                              # first parent; nothing, exit 0,
                                              # for any other commit shape
  change_scope.py --selftest                  # pinned cases against this tree
"""

import argparse
import os
import re
import subprocess
import sys

PROSE_SUFFIXES = (".md", ".mdc")
# A `#[path = "…"]` literal compiles the named file into the module that
# names it; across crates, cargo has no edge for that, so the literal is one.
MODULE_SUFFIXES = (".rs",)
WORKFLOW_SUFFIXES = (".yml", ".yaml")
SELF = "scripts/ci/change_scope.py"
JOB_OWNERS = "scripts/ci/job_owners.tsv"
RUST_WORKFLOW = ".github/workflows/rust-audit-test.yml"
RUST_JOB = "rust-audit-test:rust-audit-and-test"
# The OS builds (build.yml): the jobs its `changes` job's `work` output
# gates. The selftest holds this set to the jobs whose `if:` reads it.
BUILD_WORKFLOW = ".github/workflows/build.yml"
BUILD_JOBS = frozenset({"build:build-macos", "build:build-ubuntu", "build:build-windows-msvc"})
BUILD_GATE = "if: needs.changes.outputs.work != 'false'"
# A fuzz crate (`rust/<crate>/fuzz/`) is no workspace member and no crate's
# test: the fuzz workflows build and run it. Its manifest and lockfile are
# also read by the CI scripts that glob every fuzz crate's (the crypto
# closure record, the fuzz inventory), whose jobs own them too.
FUZZ_CRATE = re.compile(r"^rust/[^/]+/fuzz/")
FUZZ_MANIFEST = re.compile(r"^rust/[^/]+/fuzz/Cargo\.(?:toml|lock)$")
FUZZ_WORKFLOWS = (".github/workflows/fuzz-harness.yml", ".github/workflows/fuzz-nightly.yml")
FUZZ_MANIFEST_GLOB = re.compile(r"rust/\*/fuzz/Cargo\.(?:toml|lock)")
# The economics sim and the job that runs its narration pins.
SIM = "shekyl-economics-sim"
SIM_NARRATIONS_JOB = "rust-audit-test:economics-sim-narrations"
# What a narration is made of (ruled 2026-11-16): the consensus
# configuration the sim and the economics crate read, the economics crates,
# the block-weight rule, and the sim with its pin list. The selftest asserts
# each exists, so a rename cannot leave the pins with no input.
SIM_NARRATION_INPUTS = (
    "config/consensus_constants.json",
    "config/economics_params.json",
    "config/relay_policy.json",
    "rust/shekyl-chain-rules/src/rules/block_weight.rs",
    "scripts/ci/ignored_set_economics_sim.sh",
    "scripts/ci/ignored_set_mode.sh",
)
SIM_NARRATION_DIRS = ("rust/shekyl-economics/", "rust/shekyl-economics-sim/")
WORKFLOW_DIR = ".github/workflows/"
# The paths the ownership table claims. A workflow file owns its own jobs;
# any other file under the workflows directory is a plain owned path.
OWNED_DIRS = ("scripts/ci/", ".github/")
# The directories the table claims by one row each (`<dir>/`), outside
# OWNED_DIRS; the selftest holds the list to the table.
CLAIMED_DIRS = ("contrib/depends/",)


def is_workflow(path):
    return path.startswith(WORKFLOW_DIR) and path.endswith(WORKFLOW_SUFFIXES)
# An input every crate's build or test run shares: any change runs everything.
ALL_EXACT = ("rust/Cargo.toml", "rust/Cargo.lock", "rust/rust-toolchain.toml", SELF, JOB_OWNERS)
ALL_PREFIXES = ("rust/.cargo/", "rust/.config/", "config/")
# The nextest run excludes this crate (it needs the C library); the doctest
# list follows.
NEXTEST_EXCLUDED = ("shekyl-randomx-differential",)
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
CONSUMER_DIRS = ("rust/", "src/", "tests/", "contrib/")
# A step that builds in a directory under docs/ makes it a consumer tree.
DOCS_WORKING_DIRECTORY = re.compile(r"working-directory:\s*(docs/[A-Za-z0-9_./-]+)")
CONSUMING_WORKFLOWS = (
    ".github/workflows/build.yml",
    ".github/workflows/rust-audit-test.yml",
    ".github/workflows/codeql.yml",
)
# A string literal: double-quoted, no newline. Escapes are rare in paths and a
# miss here only widens what counts as an input (fail-closed).
LITERAL = re.compile(r'"([^"\n]*)"')
# A tracked input inside a literal: a `docs/` path (the docs-only question),
# or a `.github/` or `scripts/` path (the Rust-scope question: a test that
# reads a workflow file or a script runs when that file changes, whichever
# jobs own it).
TRACKED_IN_LITERAL = re.compile(r'(?:^|[/"\s(])((?:docs|\.github|scripts)/[^"\n]*)')
WHITESPACE = re.compile(r"\s")
# Where a literal stops being a fixed path: a format placeholder or a glob.
PATH_STOP = re.compile(r'[{}*$%<>?\[\]]')


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def consuming_workflow_text():
    texts = []
    for wf in CONSUMING_WORKFLOWS:
        try:
            with open(wf, encoding="utf-8") as f:
                texts.append(f.read())
        except OSError:
            raise RuntimeError(f"cannot read consuming workflow {wf}")
    return "\n".join(texts)


def docs_consumer_trees(workflow_text):
    """The directories under docs/ that a consuming workflow builds in."""
    return tuple(sorted({d.rstrip("/") + "/" for d in DOCS_WORKING_DIRECTORY.findall(workflow_text)}))


def is_prose(path, trees=()):
    if path.endswith(PROSE_SUFFIXES):
        return True
    return path.startswith("docs/") and not path.startswith(trees)


def consumer_files():
    tracked = git("ls-files").splitlines()
    text = consuming_workflow_text()
    scripts = set(re.findall(r"scripts/[A-Za-z0-9_./-]+", text))
    trees = docs_consumer_trees(text)
    out = []
    for p in tracked:
        if is_prose(p, trees):
            continue
        if p == SELF:
            continue
        if p.startswith(CONSUMER_DIRS + trees) or p in scripts:
            out.append(p)
    if not out:
        raise RuntimeError("no consumer files found; refusing to classify")
    return out


# A whole-line comment quotes paths in prose ("see `../README.md`") without
# reading them. Dropping those lines keeps a quoted mention from counting as an
# input; a trailing comment on a code line stays, which only widens the set.
# Comment syntax follows the file type. In Rust `#` opens an attribute
# (`#![doc = include_str!(…)]`), and a doc comment (`///`, `//!`, `/** */`,
# `/*! */`) holds doctests that are compiled and run, so a doctest's
# `include_str!` is a read: only a plain `//` line comment is dropped there.
RUST_COMMENT = re.compile(r"^\s*//(?![/!])")
C_LIKE = re.compile(r"^\s*(?://|/\*|\*)")
HASH = re.compile(r"^\s*#")
C_LIKE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp", ".inl", ".ipp")
HASH_SUFFIXES = (".txt", ".sh", ".py", ".ps1", ".yml", ".yaml", ".toml", ".mk")


def code_text(path):
    if path.endswith(".rs"):
        comment = RUST_COMMENT
    elif path.endswith(C_LIKE_SUFFIXES):
        comment = C_LIKE
    elif path.endswith(HASH_SUFFIXES) or os.path.basename(path) == "Makefile":
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
        parent = os.path.dirname(d)
        if parent == d:  # an absolute path's root is its own parent
            break
        d = parent
    return os.path.dirname(path)


def read_text(path):
    """A consumer's text. A file that cannot be read may be source that
    names a document, so it raises and the run fails closed. A binary file
    (a NUL in its first 8 KiB: test corpora, fixtures) holds no literal a
    compiler resolves, so it is empty text, not an error."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise RuntimeError(f"cannot read consumer {path}: {e}") from e
    if b"\0" in raw[:8192]:
        return ""
    return raw.decode("utf-8", errors="replace")


class Inputs:
    """The `docs/`, `.github/` and `scripts/` paths and the prose file names
    the consumers read, each with the consumers that name it."""

    def __init__(self, consumers):
        self.exact = set()      # a fixed path: the file, or a directory above files
        self.prefixes = set()   # a path cut at a placeholder: a plain prefix
        self.resolved = set()   # prose paths a literal resolves to, outside docs/
        self.named_by = {}      # input (exact, prefix or resolved) -> the consumers naming it
        for path in consumers:
            here = os.path.dirname(path)
            root = crate_root(path)
            for lit in LITERAL.findall(code_text(path)):
                if WHITESPACE.search(lit):
                    continue
                if lit.endswith(PROSE_SUFFIXES + MODULE_SUFFIXES) and not PATH_STOP.search(lit):
                    rel = lit.lstrip("/")
                    for base in {here, root}:
                        self._add(self.resolved, os.path.normpath(os.path.join(base, rel)), path)
                if path.startswith("docs/") and lit.startswith("../") and not PATH_STOP.search(lit):
                    for base in {here, root}:
                        target = os.path.normpath(os.path.join(base, lit))
                        if target.startswith("docs/"):
                            self._add(self.exact, target, path)
                for m in TRACKED_IN_LITERAL.finditer(lit):
                    tail = m.group(1)
                    stop = PATH_STOP.search(tail)
                    if stop:
                        self._add(self.prefixes, tail[: stop.start()], path)
                    else:
                        self._add(self.exact, os.path.normpath(tail), path)

    def _add(self, inputs, key, consumer):
        inputs.add(key)
        self.named_by.setdefault(key, set()).add(consumer)

    def readers(self, path):
        """The consumers that read `path`, by the same rules as `reads`."""
        keys = set()
        if path in self.exact:
            keys.add(path)
        keys.update(e for e in self.exact if path.startswith(e + "/"))
        keys.update(p for p in self.prefixes if path.startswith(p))
        if path in self.resolved:
            keys.add(path)
        out = set()
        for k in keys:
            out.update(self.named_by.get(k, ()))
        return out

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


def classify(files, inputs, trees):
    """Return (docs_only, reasons). A single non-documentation file decides."""
    reasons = []
    for f in files:
        if not is_prose(f, trees):
            reasons.append(f"{f}: not prose")
            return False, reasons
        why = inputs.reads(f)
        if why:
            reasons.append(f"{f}: {why}")
            return False, reasons
    return True, [f"{len(files)} file(s), all prose and read by no consumer"]


def pr_merge_parent(commit_text, pr_head):
    """The `dev` a pull request's merge commit was built on: the first parent
    of a two-parent commit whose second parent is the pull request's head,
    read from `git cat-file -p` (a shallow checkout has the header too).
    Anything else answers "", which every caller treats as no base."""
    header = commit_text.split("\n\n", 1)[0]
    parents = [line.split()[1] for line in header.splitlines() if line.startswith("parent ")]
    return parents[0] if len(parents) == 2 and pr_head and parents[1] == pr_head else ""


def pr_base(merge, pr_head):
    """`pr_merge_parent` of the commit `merge`; "" when it cannot be read."""
    try:
        return pr_merge_parent(git("cat-file", "-p", merge), pr_head)
    except Exception as e:
        print(f"scope: cannot read {merge!r} ({e})", file=sys.stderr)
        return ""


def changed_files(base, head):
    if not base or not head:
        raise RuntimeError("no base or head")
    git("cat-file", "-e", f"{base}^{{commit}}")
    files = [f for f in git("diff", "--name-only", base, head).splitlines() if f]
    if not files:
        raise RuntimeError("empty file list")
    return files


def emit(docs_only, rust_job="run", rust_tests="all", rust_doc_pkgs="", bench_rows="all", sim_narrations="run",
         build_jobs="run"):
    lines = [
        f"docs_only={'true' if docs_only else 'false'}",
        f"build_jobs={build_jobs}",
        f"rust_job={rust_job}",
        f"rust_tests={rust_tests}",
        f"rust_doc_pkgs={rust_doc_pkgs}",
        f"bench_rows={bench_rows}",
        f"sim_narrations={sim_narrations}",
    ]
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    for line in lines:
        print(f"scope: {line}")


# ---- The Rust job's scope ----------------------------------------------------


class Workspace:
    """The workspace members, their directories and the edges between them.

    `cargo metadata --no-deps` parses the workspace manifests alone (no
    registry, no network): each member's declared dependencies, every kind
    (normal, dev, build, target-specific, optional), with the path of a
    member it names. That is the same member-to-member graph nextest's
    `rdeps()` walks, since features add no edge between members that is not
    declared. `+stable` keeps rustup from installing the pinned toolchain on
    a runner that lacks it; the metadata does not depend on the version.
    """

    def __init__(self, metadata):
        members = set(metadata["workspace_members"])
        self.dir_of = {}      # package name -> its directory, relative to the repo root
        self.has_lib = {}
        self.deps = {}        # package name -> the member names it declares
        self.links = {}       # the same, without the dev-dependency edges
        by_id = {p["id"]: p for p in metadata["packages"] if p["id"] in members}
        manifests = {p["manifest_path"]: p["name"] for p in by_id.values()}
        root = metadata["workspace_root"]
        for p in by_id.values():
            rel = os.path.relpath(os.path.dirname(p["manifest_path"]), os.path.dirname(root))
            self.dir_of[p["name"]] = rel.replace(os.sep, "/") + "/"
            self.has_lib[p["name"]] = any(
                k in ("lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro")
                for t in p["targets"] for k in t["kind"]
            )
            names, linked = set(), set()
            for d in p["dependencies"]:
                path = d.get("path")
                name = None
                if path:
                    name = manifests.get(os.path.join(path, "Cargo.toml"))
                elif d["name"] in manifests.values():
                    name = d["name"]
                if name:
                    names.add(name)
                    if d.get("kind") != "dev":
                        linked.add(name)
            self.deps[p["name"]] = names
            self.links[p["name"]] = linked
        if len(self.dir_of) < 50:
            raise RuntimeError(f"only {len(self.dir_of)} workspace members read; refusing to scope")

    @classmethod
    def read(cls, rust_dir="rust"):
        import json
        last = None
        for cargo in (["cargo", "+stable"], ["cargo"]):
            try:
                out = subprocess.run(
                    [*cargo, "metadata", "--no-deps", "--offline", "--format-version", "1"],
                    cwd=rust_dir, check=True, capture_output=True, text=True,
                ).stdout
                return cls(json.loads(out))
            except (OSError, subprocess.CalledProcessError, ValueError) as e:
                last = e
        raise RuntimeError(f"cargo metadata failed: {last}")

    def package_of(self, path):
        """The member whose directory holds `path` (the deepest one), else None."""
        best = None
        for name, d in self.dir_of.items():
            if path.startswith(d) and (best is None or len(d) > len(self.dir_of[best])):
                best = name
        return best

    def rdeps(self, names, edges=None):
        """`names` and every member that depends on one of them, transitively,
        over `edges` (every declared edge unless given)."""
        edges = self.deps if edges is None else edges
        out = set(names)
        grew = True
        while grew:
            grew = False
            for name, deps in edges.items():
                if name not in out and deps & out:
                    out.add(name)
                    grew = True
        return out

    def linked_rdeps(self, names):
        """[`rdeps`] without the dev-dependency edges: the members whose
        compiled code a change to `names` reaches. A test's reach is wider
        (a dev-dependency changes what a test can observe); a benchmark
        row counts code its crate links, and a dev-dependency edge joins
        nearly every member to nearly every other."""
        return self.rdeps(names, self.links)


def read_owners(path=JOB_OWNERS):
    """path -> set of `workflow:job` owners (`none` -> empty set)."""
    owners = {}
    for line in read_text(path).splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        p, _, jobs = line.partition("\t")
        if not _:
            raise RuntimeError(f"{path}: a row without a tab: {line!r}")
        owners[p] = set() if jobs == "none" else set(jobs.split(","))
    if not owners:
        raise RuntimeError(f"{path}: no rows")
    return owners


def dir_claim(path, owners):
    """The directory row (`<dir>/`) that claims `path`, the deepest one,
    else None. Inside OWNED_DIRS every path has a row of its own."""
    rows = [d for d in owners if d.endswith("/") and path.startswith(d)]
    return max(rows, key=len) if rows and not path.startswith(OWNED_DIRS) else None


def workflow_jobs(path):
    """The job ids a workflow file defines."""
    jobs, in_jobs = [], False
    for line in read_text(path).splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        m = JOB_HEADER.match(line)
        if in_jobs and m:
            jobs.append(m.group(1))
    return jobs


def workflow_name(path):
    return os.path.basename(path).rsplit(".", 1)[0]


def jobs_naming(path, needle):
    """The `workflow:job` ids of `path`'s jobs whose steps name `needle`
    outside a comment line."""
    out, job, in_jobs = set(), None, False
    for line in read_text(path).splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        m = JOB_HEADER.match(line)
        if in_jobs and m:
            job = m.group(1)
            continue
        if in_jobs and job and needle in line and not line.lstrip().startswith("#"):
            out.add(f"{workflow_name(path)}:{job}")
    return out


def workflow_owners(path, workflows):
    """A workflow file owns the jobs it defines, and the jobs of other
    workflows that call it as a reusable workflow."""
    owners = {f"{workflow_name(path)}:{j}" for j in workflow_jobs(path)}
    for wf in workflows:
        if wf != path:
            owners |= jobs_naming(wf, path)
    return owners


def fuzz_manifest_readers():
    """The CI scripts whose code (comments aside) globs every fuzz crate's
    manifest or lockfile, read from the tree."""
    return sorted(
        s for s in git("ls-files", "scripts/ci/").splitlines()
        if s.endswith((".py", ".sh")) and FUZZ_MANIFEST_GLOB.search(code_text(s))
    )


def fuzz_owners(path, owners, workflows, readers=None):
    """The jobs a fuzz crate's file is for: the fuzz workflows' jobs, and for
    its manifest or lockfile the jobs of each script that globs them."""
    jobs = set()
    for wf in FUZZ_WORKFLOWS:
        jobs |= workflow_owners(wf, workflows)
    if FUZZ_MANIFEST.match(path):
        for s in fuzz_manifest_readers() if readers is None else readers:
            jobs |= owners.get(s, set())
    return jobs


def rust_scope(files, inputs, trees, workspace, owners, workflows, jobs=frozenset({RUST_JOB}),
               own=RUST_WORKFLOW, name="the Rust job"):
    """(rust_job, rust_tests, reasons): `rust_tests` is 'all', 'none' or a
    set of package names. Any file nothing claims decides for 'all'.

    `jobs` are the `workflow:job` ids the answer is for and `own` their
    workflow file; the defaults are the Rust job's. With BUILD_JOBS and
    BUILD_WORKFLOW the first element is `build_jobs` (`build_scope`).

    Every changed file is placed twice: by what it is (a member's file, a
    workflow file, a path the ownership table claims) and by who reads it
    (the consumers whose literals name it). A workflow file or a script is
    owned by jobs and may also be read by a crate's test, as the schema
    snapshot workflow is; both answers count."""
    pkgs, job_run, reasons = set(), False, []

    def everything(why):
        reasons.append(why)
        return "run", "all", reasons

    def place_reader(f, r):
        """A consumer that reads `f`: a member's file scopes its package; a
        script with a row scopes its jobs. Anything else cannot be placed."""
        nonlocal job_run
        p = workspace.package_of(r)
        if p is not None:
            pkgs.add(p)
            reasons.append(f"{f}: read by {r} ({p})")
            return True
        if r in owners:
            if jobs & owners[r]:
                job_run = True
            reasons.append(f"{f}: read by {r}, owned by {', '.join(sorted(owners[r])) or 'no job'}")
            return True
        return False

    for f in files:
        if f in ALL_EXACT or f.startswith(ALL_PREFIXES):
            return everything(f"{f}: an input every crate shares")
        claimed = False
        if is_workflow(f):
            if f == own:
                return everything(f"{f}: the workflow that defines {name}")
            if f not in workflows:
                return everything(f"{f}: a workflow file not in the tree")
            claimed = True
            if jobs & workflow_owners(f, workflows):
                job_run = True
                reasons.append(f"{f}: a workflow {name} calls")
            else:
                reasons.append(f"{f}: owns its own jobs, not {name}")
        elif f.startswith(OWNED_DIRS):
            if f not in owners:
                return everything(f"{f}: no row in {JOB_OWNERS}")
            claimed = True
            if jobs & owners[f]:
                job_run = True
                reasons.append(f"{f}: a file {name} runs")
            else:
                reasons.append(f"{f}: owned by {', '.join(sorted(owners[f])) or 'no job'}")
        elif FUZZ_CRATE.match(f):
            claimed = True
            if jobs & fuzz_owners(f, owners, workflows):
                job_run = True
                reasons.append(f"{f}: a fuzz crate's file {name} reads")
            else:
                reasons.append(f"{f}: a fuzz crate's file: the fuzz jobs build it, no crate tests it")
        elif (d := dir_claim(f, owners)) is not None:
            claimed = True
            if jobs & owners[d]:
                job_run = True
                reasons.append(f"{f}: under {d}, a directory {name} runs")
            else:
                reasons.append(f"{f}: under {d}, owned by {', '.join(sorted(owners[d])) or 'no job'}")
        readers = sorted(inputs.readers(f))
        for r in readers:
            if not place_reader(f, r):
                return everything(f"{f}: read by {r}, which is in no workspace member and has no row in {JOB_OWNERS}")
        if claimed:
            continue
        if not readers and is_prose(f, trees):
            reasons.append(f"{f}: prose no crate reads")
            continue
        p = workspace.package_of(f)
        if p is not None:
            pkgs.add(p)
            reasons.append(f"{f}: {p}")
            continue
        if not readers:
            return everything(f"{f}: in no workspace member and claimed by nothing")
    excluded = pkgs & set(NEXTEST_EXCLUDED)
    if excluded:
        # The job builds this crate and never runs its tests (its own
        # workflow does, under the C library); nothing depends on it.
        reasons.append(f"{', '.join(sorted(excluded))}: excluded from this job's test run")
        pkgs -= excluded
        job_run = True
    if pkgs:
        return "run", pkgs, reasons
    if job_run:
        return "run", "none", reasons
    return "skip", "none", reasons


def build_scope(files, inputs, trees, workspace, owners, workflows):
    """(build_jobs, reason): `run` when the OS builds read a changed file,
    else `skip`. They compile every workspace crate through `cargo xtask` and run
    their own scripts and actions, so a change runs them when it reaches a
    package, is an input every crate shares or one nothing claims, is
    build.yml itself, or is a file one of BUILD_JOBS runs. A change owned
    only by other jobs (another workflow, its scripts, its actions) skips
    them."""
    job, _, reasons = rust_scope(files, inputs, trees, workspace, owners, workflows,
                                 jobs=BUILD_JOBS, own=BUILD_WORKFLOW, name="an OS build job")
    return job, reasons[-1] if reasons else "no reason recorded"


def doc_pkgs(workspace, tests):
    """The `-p` arguments for `cargo test --doc` over the reverse closure of
    the scoped packages: those with a library target, minus the crate the
    nextest run excludes."""
    if tests in ("all", "none"):
        return ""
    names = sorted(n for n in workspace.rdeps(tests) if workspace.has_lib[n] and n not in NEXTEST_EXCLUDED)
    return " ".join(f"-p {n}" for n in names)


# ---- The benchmark capture's scope -------------------------------------------

LEDGER = "docs/benchmarks/measurement_ledger.toml"
BENCH_WORKFLOW = ".github/workflows/benchmarks.yml"
# A change here can move any row or the way rows are captured and compared.
BENCH_INPUT_DIRS = ("scripts/bench/",)
BENCH_INPUT_FILES = (LEDGER, BENCH_WORKFLOW)
CAPTURE_SCRIPT = "scripts/bench/capture_rust_baseline.sh"
BENCH_ROW = re.compile(r'\s*"([a-z0-9-]+):[a-z0-9_]*:([a-z0-9_]+)(?::[^"]*)?"\s*')


def pr_capture_rows(path=CAPTURE_SCRIPT):
    """The rows of the capture script's `BENCHES` array, the set a pull
    request's capture draws from, as `<crate>::<gungraun-target>`. The
    nightly set (`NIGHTLY_BENCHES`) is not a pull request's to run."""
    block = re.search(r"^BENCHES=\(\n(.*?)^\)", read_text(path), re.M | re.S)
    rows = {f"{m.group(1)}::{m.group(2)}" for line in (block.group(1).splitlines() if block else []) if (m := BENCH_ROW.fullmatch(line))}
    if not rows:
        raise RuntimeError(f"{path}: no BENCHES row")
    return rows


def read_gated_rows(path=LEDGER):
    """[(bench, spec)]: each `[[gated_row]]` of the ledger that is a row of
    the pull-request set, with its path set's included paths. A row on an
    undefined path set, a pull-request row with no gated row, or none at
    all, is an error: the caller fails closed to `all`."""
    import tomllib

    data = tomllib.loads(read_text(path))
    specs = {s["id"]: tuple(p for p in s["spec"] if not p.startswith((":!", ":(exclude)", ":^"))) for s in data.get("path_set", [])}
    captured = pr_capture_rows()
    rows = [(row["bench"], specs[row["path_set"]]) for row in data.get("gated_row", []) if row["bench"] in captured]
    unnamed = captured - {bench for bench, _ in rows}
    if unnamed:
        raise RuntimeError(f"{path}: no gated row for {sorted(unnamed)}")
    return rows


def under(path, root):
    """`path` is `root` or lies beneath it."""
    root = root.rstrip("/")
    return path == root or path.startswith(root + "/")


def bench_rows(files, tests, workspace, rows):
    """`all`, `none` or the sorted rows `files` can move (module docstring)."""
    if tests == "all":
        return "all"
    if any(f in BENCH_INPUT_FILES or f.startswith(BENCH_INPUT_DIRS) for f in files):
        return "all"
    closure = workspace.linked_rdeps(tests) if isinstance(tests, set) else set()
    hit = sorted(
        bench
        for bench, spec in rows
        if any(workspace.package_of(p.rstrip("/") + "/") in closure for p in spec)
        or any(under(f, p) for f in files for p in spec)
    )
    return " ".join(hit) if hit else "none"


def sim_narrations_scope(files):
    """(`run` or `skip`, reason) for the sim's narration pins over the
    changed `files`."""
    for f in files:
        if f in SIM_NARRATION_INPUTS or f.startswith(SIM_NARRATION_DIRS):
            return "run", f"{f}: a narration input"
    return "skip", "no narration input changed"


def rust_tests_value(tests):
    return tests if isinstance(tests, str) else " ".join(sorted(tests))


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
    ("README.md", True),                                  # no consumer reads it
    ("rust/shekyl-tor/src/lib.rs", False),                # any .rs, doc comment or not
    ("rust/xtask/matrix.toml", False),
    ("src/cryptonote_basic/account.cpp", False),
    (".github/workflows/build.yml", False),
    ("scripts/ci/change_scope.py", False),
    ("docs/formal/checkct/dynamic/src/main.rs", False),   # a crate the rust job builds under docs/
    ("docs/formal/checkct/dynamic/Cargo.lock", False),
    ("docs/formal/checkct/results/2026-10-24/dynamic-aarch64-floor-device.txt", False),  # its tests read the records
    ("docs/formal/checkct/README.md", True),              # prose beside that crate stays prose
    ("docs/formal/checkct/drivers/ctl.rs", True),         # the static harness: no consuming workflow builds it
]


def selftest():
    inputs = Inputs(consumer_files())
    trees = docs_consumer_trees(consuming_workflow_text())
    bad = 0
    for path, want in SELFTEST:
        got, reasons = classify([path], inputs, trees)
        ok = got == want
        bad += not ok
        print(f"[{'ok' if ok else 'WRONG'}] {path}: docs_only={got} (want {want}) — {reasons[-1]}")
    # Subject assertion (rule 47): the scan found the inputs the cases rely on.
    if "docs/design/CRYPTO_DOMAIN_REGISTRY.tsv" not in inputs.exact:
        print("WRONG: the scan did not find the domain registry's include_str!")
        bad += 1
    if "docs/formal/checkct/dynamic/" not in trees:
        print(f"WRONG: the scan did not find the docs consumer tree the rust job builds: {trees}")
        bad += 1
    # The whitespace exclusion narrows what counts as an input. It is safe
    # only while no prose path contains whitespace; assert that here, so a
    # path with a space fails the gate instead of skipping a build quietly.
    spaced = [p for p in git("ls-files").splitlines() if is_prose(p) and WHITESPACE.search(p)]
    if spaced:
        print(f"WRONG: prose paths contain whitespace, so a read of one would be missed: {spaced[:5]}")
        bad += 1
    # A sentence that mentions a document reads nothing (the staking
    # sim names docs/FOLLOWUPS.md in messages).
    if inputs.reads("docs/FOLLOWUPS.md"):
        print("WRONG: a prose mention of docs/FOLLOWUPS.md counted as a read")
        bad += 1
    # A doctest in a Rust doc comment is compiled: its include_str! is a read,
    # while a plain // comment that quotes a path is not.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "lib.rs")
        with open(src, "w", encoding="utf-8") as f:
            f.write('/// let s = include_str!("../docs/doctest_input.md");\n'
                    '// see "../docs/plain_comment.md"\n')
        probe = Inputs([src])
        if not probe.reads("docs/doctest_input.md"):
            print("WRONG: a doctest's include_str! of a document was not counted as a read")
            bad += 1
        if probe.reads("docs/plain_comment.md"):
            print("WRONG: a path quoted in a plain // comment counted as a read")
            bad += 1
        # An unreadable consumer fails closed rather than counting as empty.
        try:
            Inputs([os.path.join(tmp, "missing.rs")])
            print("WRONG: an unreadable consumer was read as empty")
            bad += 1
        except RuntimeError:
            pass
    # A mixed change is decided by its one code file.
    got, _ = classify(["docs/design/TOR_SUPERVISOR.md", "rust/shekyl-tor/src/lib.rs"], inputs, trees)
    if got:
        print("WRONG: a docs file plus a .rs file was called docs-only")
        bad += 1
    bad += rust_selftest(inputs, trees)
    bad += build_selftest(inputs, trees)
    bad += fuzz_selftest()
    bad += pr_base_selftest()
    print(f"selftest: {'FAILED' if bad else 'ok'} ({bad} wrong)")
    return 1 if bad else 0


# (path, expected build_jobs) for a change of that file alone
BUILD_SELFTEST = [
    ("rust/shekyl-units/src/lib.rs", "run"),                    # a package: the builds compile it
    ("rust/shekyl-fcmp/fuzz/fuzz_targets/x.rs", "skip"),        # a fuzz harness: the fuzz jobs build it
    ("rust/shekyl-levin/fuzz/Cargo.lock", "skip"),              # read by the fuzz and Rust jobs' scripts, not the builds
    ("docs/test_vectors/PQC_HYBRID_V2_KAT.json", "run"),        # read by crates' tests
    ("rust/Cargo.lock", "run"),
    ("config/anything.h", "run"),
    ("contrib/brew/Brewfile", "run"),                           # claimed by nothing
    ("rust/xtask/matrix.toml", "run"),
    ("external/randomx-v2/src/x.c", "run"),
    (SELF, "run"),
    (JOB_OWNERS, "run"),
    (BUILD_WORKFLOW, "run"),                                    # their own workflow
    ("scripts/ci/check_binary_hardening.sh", "run"),            # a step of theirs runs it
    ("scripts/ci/run_live_daemon_gates.sh", "run"),             # the Ubuntu build's live-daemon gates
    (".github/actions/install-rust/action.yml", "run"),         # an action they use
    (".github/actions/install-rust/action.yml", "run"),
    (".github/workflows/merge-ready.yml", "skip"),              # owns its own jobs
    (".github/workflows/docs-gates.yml", "skip"),
    (RUST_WORKFLOW, "skip"),                                    # the Rust job's, not theirs
    ("scripts/ci/merge_ready.py", "skip"),                      # owned by other jobs
    ("scripts/ci/check_doc_links.py", "skip"),
    ("scripts/ci/push_scope_base.sh", "skip"),                  # the scope job's, which always runs
    ("scripts/ci/workflow_pass.py", "skip"),                    # the pass job's, which always runs
    ("contrib/depends/Makefile", "skip"),                       # depends.yml's tree
    (".github/CODEOWNERS", "skip"),
]


def build_selftest(inputs, trees):
    bad = 0
    workspace = Workspace.read()
    owners = read_owners()
    workflows = sorted(w for w in git("ls-files", WORKFLOW_DIR).splitlines() if w.endswith((".yml", ".yaml")))
    for path, want in BUILD_SELFTEST:
        got, why = build_scope([path], inputs, trees, workspace, owners, workflows)
        bad += got != want
        print(f"[{'ok' if got == want else 'WRONG'}] {path}: build_jobs={got} — {why}")
    # One file the builds read decides for the whole change.
    got, _ = build_scope(["scripts/ci/merge_ready.py", "rust/shekyl-units/src/lib.rs"],
                         inputs, trees, workspace, owners, workflows)
    if got != "run":
        print(f"WRONG: another job's script + a crate gave build_jobs={got}")
        bad += 1
    # BUILD_JOBS is exactly the jobs build.yml gates on `work`, and the
    # `work` step reads this output (rule 47: the subject exists).
    text = read_text(BUILD_WORKFLOW)
    gated, job = set(), None
    for line in text.splitlines():
        m = JOB_HEADER.match(line)
        if m:
            job = m.group(1)
        elif job and line.strip() == BUILD_GATE:
            gated.add(f"{workflow_name(BUILD_WORKFLOW)}:{job}")
    if gated != BUILD_JOBS:
        print(f"WRONG: {BUILD_WORKFLOW} gates {sorted(gated)} on `work`; BUILD_JOBS is {sorted(BUILD_JOBS)}")
        bad += 1
    for needle in ("BUILD_JOBS: ${{ steps.scope.outputs.build_jobs }}", '[ "$BUILD_JOBS" = "skip" ]'):
        if needle not in text:
            print(f"WRONG: {BUILD_WORKFLOW}'s `work` step lacks {needle!r}")
            bad += 1
    return bad


# The workflows whose scope reads a pull request's base: from `--pr-base`,
# never the event's `pull_request.base.sha`.
PR_BASE_WORKFLOWS = tuple(f".github/workflows/{w}.yml" for w in (
    "benchmarks", "build", "chain-forge", "codeql", "depends", "doc-claims", "fuzz-harness", "rust-audit-test"))


def pr_base_selftest():
    bad = 0
    dev, head, other = "d" * 40, "e" * 40, "f" * 40
    commit = lambda *parents: "tree 1\n" + "".join(f"parent {p}\n" for p in parents) + "author a\n\nparent " + other
    for label, text, pr_head, want in [
        ("a pull request's merge commit", commit(dev, head), head, dev),
        # Negative controls: each is no base, which runs everything.
        ("another pull request's merge", commit(dev, other), head, ""),
        ("parents the wrong way round", commit(head, dev), head, ""),
        ("a commit with one parent", commit(dev), head, ""),
        ("a root commit", commit(), head, ""),
        ("an octopus merge", commit(dev, head, other), head, ""),
        ("no pull request head", commit(dev, head), "", ""),
    ]:
        got = pr_merge_parent(text, pr_head)
        if got != want:
            print(f"WRONG: pr_merge_parent, {label}: {got!r}, want {want!r}")
            bad += 1
    for path in PR_BASE_WORKFLOWS:
        text = read_text(path)
        if "change_scope.py --pr-base" not in text or "pull_request.base.sha" in text:
            print(f"WRONG: {path} does not take a pull request's base from --pr-base alone")
            bad += 1
    # The audit reads the step output. A local run exits at the fetch guard,
    # so the base has to be published before that exit.
    claims = read_text(".github/workflows/doc-claims.yml")
    published = claims.find('echo "base=$base" >> "$GITHUB_OUTPUT"')
    guard = claims.find('if [ "${GITHUB_ACTIONS:-}" != "true" ]; then')
    fetch = claims.find("git fetch --no-tags --depth=1 origin")
    if not (0 <= published < guard < fetch):
        print("WRONG: doc-claims.yml publishes the base after its fetch guard or its fetch")
        bad += 1
    return bad


def fuzz_selftest():
    """The subjects the fuzz placement reads exist (rule 47): the fuzz
    workflows, a fuzz crate, and the crypto closure script among the
    readers of every fuzz manifest, which is why a fuzz lockfile runs the
    Rust job."""
    bad = 0
    tracked = set(git("ls-files").splitlines())
    for wf in FUZZ_WORKFLOWS:
        if wf not in tracked:
            print(f"WRONG: FUZZ_WORKFLOWS names {wf}, which is not tracked")
            bad += 1
    if not any(FUZZ_MANIFEST.match(f) for f in tracked):
        print("WRONG: no rust/<crate>/fuzz/Cargo.toml or Cargo.lock is tracked")
        bad += 1
    if "scripts/ci/check_crypto_closure.py" not in fuzz_manifest_readers():
        print(f"WRONG: the crypto closure script is not among the fuzz manifest readers {fuzz_manifest_readers()}")
        bad += 1
    return bad


# (path, expected rust_job, expected rust_tests) for a change of that file alone
RUST_SELFTEST = [
    ("rust/shekyl-units/src/lib.rs", "run", {"shekyl-units"}),
    ("rust/shekyl-wire/fuzz/Cargo.toml", "run", "none"),                   # a fuzz crate: no crate's test; the crypto closure step reads it
    ("rust/shekyl-levin/fuzz/Cargo.lock", "run", "none"),                  # likewise its lockfile
    ("rust/shekyl-fcmp/fuzz/fuzz_targets/x.rs", "skip", "none"),           # a harness: fuzz-harness.yml builds it, no crate tests it
    ("rust/shekyl-mempool/Cargo.toml", "run", {"shekyl-mempool"}),         # a dependency edit: rdeps covers the consumers
    ("rust/Cargo.toml", "run", "all"),
    ("rust/Cargo.lock", "run", "all"),
    ("rust/rust-toolchain.toml", "run", "all"),
    ("rust/.config/nextest.toml", "run", "all"),
    ("rust/.cargo/config.toml", "run", "all"),
    ("config/anything.h", "run", "all"),                                   # read by build scripts
    ("contrib/brew/Brewfile", "run", "all"),                               # claimed by nothing
    ("external/randomx-v2/src/x.c", "run", "all"),
    (SELF, "run", "all"),
    (JOB_OWNERS, "run", "all"),
    (RUST_WORKFLOW, "run", "all"),
    (".github/workflows/docs-gates.yml", "skip", "none"),                  # owns its own jobs
    (".github/workflows/report-dev-red.yml", "skip", "none"),              # called by the reporter jobs, not the Rust job
    (".github/actions/install-rust/action.yml", "run", "none"),            # the Rust job uses it
    (".github/CODEOWNERS", "skip", "none"),
    ("scripts/ci/nextest_report.py", "run", "none"),                       # the Rust job runs it: its gate steps, no test
    ("scripts/ci/ignored_set_mode.sh", "run", "none"),                     # sourced by the lane scripts the job runs
    ("scripts/ci/check_doc_links.py", "skip", "none"),                     # a documentation gate
    ("scripts/ci/p17_remote_dial.ps1", "skip", "none"),                    # claimed, run by no job
    ("docs/design/CRYPTO_DOMAIN_REGISTRY.tsv", "run", None),               # the crates whose tests include_str! it
    ("docs/test_vectors/PQC_HYBRID_V2_KAT.json", "run", None),             # read at test time
    ("docs/FOLLOWUPS.md", "skip", "none"),                                 # prose (docs-only decides the job anyway)
    ("rust/shekyl-randomx-differential/src/lib.rs", "run", "none"),        # built here, tested by its own workflow
    (".github/workflows/schema-snapshot.yml", "run", None),                # owns its jobs, and three crates' tests read it
    ("scripts/armed_lever.py", "run", {"shekyl-cli"}),                     # outside scripts/ci: a regtest test runs it
]

# The narration pins' scope: (changed files, expected sim_narrations).
SIM_NARRATIONS_SELFTEST = [
    # #1323's shape: the surge factor in config/, its crates, merged green
    # while the narrations moved.
    (["config/consensus_constants.json", "rust/shekyl-economics/src/params.rs",
      "rust/shekyl-chain-rules/src/rules/block_weight.rs"], "run"),
    (["rust/shekyl-economics/src/params.rs"], "run"),                       # a crate the sim calls
    (["rust/shekyl-chain-rules/src/rules/block_weight.rs"], "run"),
    (["rust/shekyl-economics-sim/tests/fixtures/stage2_narration.txt"], "run"),  # a pin's fixture
    (["scripts/ci/ignored_set_economics_sim.sh"], "run"),                  # the pin list
    (["scripts/ci/ignored_set_mode.sh"], "run"),                           # sourced by it
    (["rust/shekyl-tor/src/lib.rs"], "skip"),                              # nothing the sim reads
    (["scripts/ci/nextest_report.py"], "skip"),                            # the Rust job's, not the pins'
    (["scripts/ci/check_doc_links.py"], "skip"),
    (["config/relay_policy.json"], "run"),                                 # the economics crate's fee floor reads it
    (["rust/shekyl-economics-sim/src/engine.rs"], "run"),                  # the sim
    (["rust/Cargo.lock"], "skip"),                                         # every crate's tests run; the pins do not
    (["rust/rust-toolchain.toml"], "skip"),
    ([".github/workflows/rust-audit-test.yml"], "skip"),                   # the scratch push of #1414 ran them on this
    (["config/tor_pins.json"], "skip"),                                    # config/, not a narration input
    (["rust/shekyl-chain-rules/src/rules/difficulty.rs"], "skip"),               # another rule
    (["rust/shekyl-fcmp/src/lib.rs"], "skip"),                             # in the sim's closure, not a narration input
    ([".github/actions/install-rust/action.yml"], "skip"),
]
# A workflow file or an owned path a crate's test reads: the readers, not
# only the owners, decide (rule 47: the readers are asserted to exist).
WORKFLOW_READERS = {
    ".github/workflows/schema-snapshot.yml": {"shekyl-chain-store", "shekyl-engine-state", "shekyl-peerlist"},
}
# `#[path = "…"]` crossing a crate boundary compiles another member's file
# into this one's tests. Cargo has no edge for it, so rdeps() alone misses
# the includer; the literal scan places it. The selftest asserts that for
# every such include in the tree, and that the scan found the known one,
# whose includer has no dependency edge to lean on.
MOD_PATH = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')
KNOWN_CROSS_CRATE_PATH = ("rust/shekyl-rpc-channel/src/pinned_handshake.rs", "shekyl-rpc-channel-xcheck")


def rust_selftest(inputs, trees):
    bad = 0
    workspace = Workspace.read()
    owners = read_owners()
    workflows = sorted(w for w in git("ls-files", WORKFLOW_DIR).splitlines() if w.endswith((".yml", ".yaml")))
    for path, want_job, want_tests in RUST_SELFTEST:
        job, tests, reasons = rust_scope([path], inputs, trees, workspace, owners, workflows)
        ok = job == want_job and (want_tests is None and isinstance(tests, set) and tests or tests == want_tests)
        bad += not ok
        print(f"[{'ok' if ok else 'WRONG'}] {path}: rust_job={job} rust_tests={rust_tests_value(tests)} — {reasons[-1]}")
    # A mixed change takes the union; one shared input decides for all.
    job, tests, _ = rust_scope(["docs/FOLLOWUPS.md", "rust/shekyl-units/src/lib.rs", "scripts/ci/check_doc_links.py"], inputs, trees, workspace, owners, workflows)
    if (job, tests) != ("run", {"shekyl-units"}):
        print(f"WRONG: prose + a crate + a docs gate gave {job} {rust_tests_value(tests)}")
        bad += 1
    job, tests, _ = rust_scope(["rust/shekyl-units/src/lib.rs", "rust/Cargo.lock"], inputs, trees, workspace, owners, workflows)
    if tests != "all":
        print(f"WRONG: a crate + the lock file gave {rust_tests_value(tests)}")
        bad += 1
    # A file jobs own and crates read scopes both.
    for path, want in WORKFLOW_READERS.items():
        job, tests, _ = rust_scope([path], inputs, trees, workspace, owners, workflows)
        got = tests if isinstance(tests, set) else set()
        if job != "run" or not want <= got:
            print(f"WRONG: {path} is read by {sorted(want)}; the scope gave {job} {rust_tests_value(tests)}")
            bad += 1
    # No workflow file or owned path falls back to all, bar the three that
    # share with every crate (the ruling of 2026-11-09).
    tracked_owned = git("ls-files", *OWNED_DIRS).splitlines()
    fell_back = []
    for path in tracked_owned:
        if path in ALL_EXACT or path == RUST_WORKFLOW:
            continue
        job, tests, reasons = rust_scope([path], inputs, trees, workspace, owners, workflows)
        if tests == "all":
            fell_back.append(f"{path}: {reasons[-1]}")
    if fell_back:
        print(f"WRONG: {len(fell_back)} owned path(s) fall back to all: {fell_back[:5]}")
        bad += 1
    # Every cross-crate `#[path]` include scopes the includer's package.
    crossings, uncovered = [], []
    for src in git("ls-files", "rust/*.rs").splitlines():
        here, me = os.path.dirname(src), workspace.package_of(src)
        for lit in MOD_PATH.findall(code_text(src)):
            target = os.path.normpath(os.path.join(here, lit))
            them = workspace.package_of(target)
            if them is None or them == me:
                continue
            crossings.append((src, them))
            _, tests, _ = rust_scope([target], inputs, trees, workspace, owners, workflows)
            if not (isinstance(tests, set) and me in tests):
                uncovered.append(f"{src} includes {target} ({them}); a change there gave {rust_tests_value(tests)}")
    if KNOWN_CROSS_CRATE_PATH not in crossings:
        print(f"WRONG: the #[path] scan did not find {KNOWN_CROSS_CRATE_PATH}; {len(crossings)} crossing(s) found")
        bad += 1
    if uncovered:
        print(f"WRONG: {len(uncovered)} cross-crate #[path] include(s) do not scope the includer: {uncovered[:5]}")
        bad += 1
    # Subject assertions (rule 47): the graph the scope stands on was read.
    if len(workspace.dir_of) < 100:
        print(f"WRONG: {len(workspace.dir_of)} workspace members read")
        bad += 1
    units = workspace.rdeps({"shekyl-units"})
    if len(units) < 50:
        print(f"WRONG: rdeps(shekyl-units) is {len(units)} members; the graph is missing edges")
        bad += 1
    # A dev-dependency is an edge: a fixture's change runs its consumers' tests.
    if "shekyl-mempool" not in workspace.rdeps({"shekyl-store-codec"}):
        print("WRONG: shekyl-mempool (store-codec is its dev-dependency) is not in rdeps(shekyl-store-codec)")
        bad += 1
    if any(workspace.deps[n] & set(NEXTEST_EXCLUDED) for n in workspace.deps):
        print("WRONG: a member depends on the crate the nextest run excludes; its scope would be cut")
        bad += 1
    docs = doc_pkgs(workspace, {"shekyl-tor-transit-spike"})
    if docs != "":
        print(f"WRONG: a binary-only crate got doctest packages: {docs}")
        bad += 1
    if "-p shekyl-randomx-differential" in doc_pkgs(workspace, {"shekyl-units"}):
        print("WRONG: the crate the nextest run excludes is in the doctest list")
        bad += 1
    if "-p shekyl-economics-sim" in doc_pkgs(workspace, {"shekyl-economics"}):
        print("WRONG: the sim has no library target and cannot take cargo test --doc")
        bad += 1
    # The narration pins run where the sim can move.
    for paths, want in SIM_NARRATIONS_SELFTEST:
        got, why = sim_narrations_scope(paths)
        ok = got == want
        bad += not ok
        print(f"[{'ok' if ok else 'WRONG'}] {' + '.join(paths)}: sim_narrations={got} — {why}")
    if SIM not in workspace.dir_of:
        print(f"WRONG: {SIM} is not a workspace member; the narration scope has no subject")
        bad += 1
    tree = set(git("ls-files").splitlines())
    for path in SIM_NARRATION_INPUTS:
        if path not in tree:
            print(f"WRONG: narration input {path} is not in the tree")
            bad += 1
    for d in SIM_NARRATION_DIRS:
        if not any(t.startswith(d) for t in tree):
            print(f"WRONG: narration input {d} holds no tracked file")
            bad += 1
    # The ownership table against the tree.
    tracked = [t for t in git("ls-files", *OWNED_DIRS).splitlines() if not is_workflow(t)]
    missing = [t for t in tracked if t not in owners]
    if missing:
        print(f"WRONG: {len(missing)} tracked path(s) have no row in {JOB_OWNERS}: {missing[:5]}")
        bad += 1
    dirs = sorted(p for p in owners if p.endswith("/"))
    if tuple(dirs) != CLAIMED_DIRS:
        print(f"WRONG: the directory rows of {JOB_OWNERS} are {dirs}, not CLAIMED_DIRS {list(CLAIMED_DIRS)}")
        bad += 1
    for d in dirs:
        if d.startswith(OWNED_DIRS) or not any(t.startswith(d) for t in tree):
            print(f"WRONG: directory row {d} is inside {OWNED_DIRS} or holds no tracked file")
            bad += 1
        else:
            for path in sorted(t for t in tree if t.startswith(d)):
                job, tests, reasons = rust_scope([path], inputs, trees, workspace, owners, workflows)
                if tests == "all":
                    print(f"WRONG: {path}, under directory row {d}, falls back to all: {reasons[-1]}")
                    bad += 1
                    break
    if "contrib/depends/" in dirs:
        job, tests, reasons = rust_scope(["contrib/depends/Makefile"], inputs, trees, workspace, owners, workflows)
        if (job, tests) != ("skip", "none"):
            print(f"WRONG: the depends Makefile gave {job} {rust_tests_value(tests)}: {reasons}")
            bad += 1
    stale = [p for p in owners if p not in tracked and p not in dirs]
    if stale:
        print(f"WRONG: {len(stale)} row(s) in {JOB_OWNERS} name a path that is not tracked (or is a workflow file): {stale[:5]}")
        bad += 1
    jobs = {f"{workflow_name(w)}:{j}" for w in workflows for j in workflow_jobs(w)}
    unknown = sorted({o for os_ in owners.values() for o in os_ if o not in jobs})
    if unknown:
        print(f"WRONG: {JOB_OWNERS} names job(s) no workflow defines: {unknown[:5]}")
        bad += 1
    if len(jobs) < 30:
        print(f"WRONG: only {len(jobs)} jobs read from the workflows")
        bad += 1
    under = []
    for path in owners:
        named_by = set()
        for w in workflows:
            needle = os.path.dirname(path) if path.endswith("/action.yml") else path
            named_by |= jobs_naming(w, needle)
        if named_by - owners[path]:
            under.append(f"{path} <- {sorted(named_by - owners[path])}")
    if under:
        print(f"WRONG: {len(under)} path(s) are named by a job their row does not list: {under[:5]}")
        bad += 1
    for job in (RUST_JOB, SIM_NARRATIONS_JOB):
        if job not in jobs:
            print(f"WRONG: {job} is not a job the workflows define")
            bad += 1
    return bad + bench_selftest(inputs, trees, workspace, owners, workflows)


# (path, rows that must be in scope, rows that must not; "all"/"none" exact)
BENCH_SELFTEST = [
    ("rust/shekyl-engine-state/src/lib.rs", {"shekyl-engine-state::ledger_iai"}, {"shekyl-chain-ingest::block_path_iai", "shekyl-pow-randomx::verify_header_iai"}),
    ("rust/shekyl-chain-store/src/store/connect.rs", {"shekyl-chain-ingest::block_path_iai"}, {"shekyl-engine-state::ledger_iai", "shekyl-engine-file::open_iai", "shekyl-pow-randomx::verify_header_iai"}),
    ("rust/shekyl-pow-randomx/src/vm.rs", {"shekyl-pow-randomx::verify_header_iai"}, {"shekyl-engine-state::ledger_iai"}),
    # Crates the block path links and its path set does not list: the
    # closure reaches the row through a listed crate that links them.
    ("rust/shekyl-crypto-hash/src/lib.rs", {"shekyl-chain-ingest::block_path_iai"}, set()),
    ("rust/shekyl-curve-io/src/lib.rs", {"shekyl-chain-ingest::block_path_iai"}, set()),
    ("rust/shekyl-chain-ingest/src/target.rs", {"shekyl-chain-ingest::block_path_iai"}, {"shekyl-engine-state::ledger_iai"}),
    ("rust/shekyl-chain-ingest/benches/fixtures/block_path_spend_1in_2out_unit.corpus", {"shekyl-chain-ingest::block_path_iai"}, {"shekyl-engine-state::ledger_iai"}),
    # The network and sync rows. A path set names packages. The runtime
    # and the RPC server are dev-dependencies of the bench crate, so a
    # change there reaches only the rows that name that package. Naming
    # `shekyl-chain-ingest` selects every row that names it, which is why
    # a template change also runs the block path, the body exchange and
    # the wallet read.
    ("rust/shekyl-chain-sync-runtime/src/serve.rs", {"shekyl-chain-ingest::serve_bodies_iai", "shekyl-chain-ingest::levin_bodies_iai"}, {"shekyl-engine-state::ledger_iai", "shekyl-p2p-transport::c5_iai", "shekyl-chain-ingest::block_path_iai", "shekyl-chain-ingest::block_template_iai", "shekyl-chain-ingest::wallet_block_read_iai"}),
    ("rust/shekyl-daemon-rpc/src/reads.rs", {"shekyl-chain-ingest::wallet_block_read_iai"}, {"shekyl-engine-state::ledger_iai", "shekyl-p2p-transport::c5_iai", "shekyl-chain-ingest::block_path_iai", "shekyl-chain-ingest::serve_bodies_iai", "shekyl-chain-ingest::levin_bodies_iai", "shekyl-chain-ingest::block_template_iai"}),
    ("rust/shekyl-levin/src/reader.rs", {"shekyl-chain-ingest::levin_bodies_iai", "shekyl-chain-ingest::serve_bodies_iai", "shekyl-chain-ingest::block_path_iai", "shekyl-chain-ingest::block_template_iai", "shekyl-chain-ingest::wallet_block_read_iai"}, {"shekyl-engine-state::ledger_iai", "shekyl-p2p-transport::c5_iai"}),
    ("rust/shekyl-block-template/src/lib.rs", {"shekyl-chain-ingest::block_template_iai", "shekyl-chain-ingest::block_path_iai", "shekyl-chain-ingest::serve_bodies_iai", "shekyl-chain-ingest::levin_bodies_iai", "shekyl-chain-ingest::wallet_block_read_iai"}, {"shekyl-engine-state::ledger_iai", "shekyl-p2p-transport::c5_iai"}),
    # Noise reaches the transport, and through it the runtime and the RPC
    # server; since RT-W11 it reaches `shekyl-rpc-transport` too (the RPC
    # channel's initiator lives there, Rick 2026-11-15), and through it
    # `shekyl-chain-ingest` and `shekyl-engine-core`, so the block path, the
    # template and the engine's rows run. The ledger, which reaches neither,
    # stays out.
    ("rust/shekyl-noise/src/direction.rs", {"shekyl-p2p-transport::c5_iai", "shekyl-chain-ingest::serve_bodies_iai", "shekyl-chain-ingest::levin_bodies_iai", "shekyl-chain-ingest::wallet_block_read_iai", "shekyl-chain-ingest::block_path_iai", "shekyl-chain-ingest::block_template_iai", "shekyl-engine-core::engine_trait_bench_ledger_balance_iai"}, {"shekyl-engine-state::ledger_iai"}),
    ("rust/shekyl-p2p-transport/src/channel.rs", {"shekyl-p2p-transport::c5_iai", "shekyl-chain-ingest::serve_bodies_iai", "shekyl-chain-ingest::levin_bodies_iai", "shekyl-chain-ingest::wallet_block_read_iai"}, {"shekyl-engine-state::ledger_iai", "shekyl-chain-ingest::block_path_iai", "shekyl-chain-ingest::block_template_iai"}),
    ("rust/shekyl-engine-core/src/lib.rs", set(), {"shekyl-chain-ingest::serve_bodies_iai", "shekyl-chain-ingest::levin_bodies_iai", "shekyl-chain-ingest::block_template_iai", "shekyl-chain-ingest::wallet_block_read_iai", "shekyl-p2p-transport::c5_iai"}),
    ("rust/Cargo.lock", "all", None),
    ("scripts/bench/compare.py", "all", None),
    (BENCH_WORKFLOW, "all", None),
    (LEDGER, "all", None),
    ("scripts/ci/check_doc_links.py", "none", None),
]


def bench_selftest(inputs, trees, workspace, owners, workflows):
    bad = 0
    rows = read_gated_rows()
    names = {bench for bench, _ in rows}
    for path, want, never in BENCH_SELFTEST:
        _, tests, _ = rust_scope([path], inputs, trees, workspace, owners, workflows)
        got = bench_rows([path], tests, workspace, rows)
        if isinstance(want, str):
            ok = got == want
        else:
            hit = set(got.split())
            ok = got not in ("all", "none") and want <= hit and not (never & hit) and (want | never) <= names
        print(f"[{'ok' if ok else 'WRONG'}] {path}: bench_rows={got}")
        bad += 0 if ok else 1
    # A row whose path set does not reach its own crate would stay out of
    # scope when that crate changes: the closure could not find it.
    for bench, spec in rows:
        crate = bench.split("::")[0]
        if not any(workspace.package_of(p.rstrip("/") + "/") == crate for p in spec):
            print(f"WRONG: gated row {bench}: no path of its path set lies in {crate}")
            bad += 1
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base")
    ap.add_argument("--head")
    ap.add_argument("--files", nargs="+")
    ap.add_argument("--pr-base", nargs=2, metavar=("MERGE", "PR_HEAD"))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.pr_base:
        base = pr_base(*args.pr_base)
        if not base:
            print(f"scope: {args.pr_base[0]} is not this pull request's merge commit", file=sys.stderr)
        print(base)
        return 0
    try:
        files = args.files or changed_files(args.base, args.head)
        trees = docs_consumer_trees(consuming_workflow_text())
        inputs = Inputs(consumer_files())
        docs_only, reasons = classify(files, inputs, trees)
        if docs_only:
            job, tests, more = "skip", "none", ["docs only: the Rust job is skipped"]
            docs = ""
            bench = "none"
            narrations = "skip"
            build = "skip"
        else:
            workspace = Workspace.read()
            owners = read_owners()
            workflows = sorted(w for w in git("ls-files", WORKFLOW_DIR).splitlines() if w.endswith((".yml", ".yaml")))
            job, tests, more = rust_scope(files, inputs, trees, workspace, owners, workflows)
            docs = doc_pkgs(workspace, tests)
            bench = bench_rows(files, tests, workspace, read_gated_rows())
            narrations, why = sim_narrations_scope(files)
            build, build_why = build_scope(files, inputs, trees, workspace, owners, workflows)
            more = more + [f"sim narrations {narrations}: {why}", f"OS builds {build}: {build_why}"]
    except Exception as e:  # fail closed on anything
        print(f"scope: cannot decide ({e}); running everything (fail-closed)")
        emit(False)
        return 0
    for r in reasons + more:
        print(f"scope: {r}")
    emit(docs_only, job, rust_tests_value(tests), docs, bench, narrations, build)
    return 0


if __name__ == "__main__":
    sys.exit(main())
