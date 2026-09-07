# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Falsification matrix for check_doc_claims.py — committed alongside the gate
# because a gate whose failure paths are only asserted in a PR body is a gate
# nobody can re-check after the next refactor. This is runnable: re-run it
# whenever the gate changes, exactly as the P0b review had to re-falsify a
# coverage gate after its legs were refactored.
#
# It builds a synthetic docs corpus in a temporary tree and runs the gate
# against THAT, so it never edits the repository. That choice is deliberate:
# an earlier mutation harness in this program truncated a 10,000-line source
# file to zero because `open(path, "w")` truncates before the transform that
# feeds it can raise. A matrix that cannot damage the tree cannot repeat it.
#
# Every case asserts a SPECIFIC message fragment, not merely a non-zero exit.
# A leg that fails for the wrong reason is a leg that is not being tested, and
# "it went red" is the weakest possible evidence that it went red on its own
# axis.

import ast
import atexit
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

GATE = pathlib.Path(__file__).resolve().parent / "check_doc_claims.py"

# ── outcome coverage ──────────────────────────────────────────────────────────
# Every case below was written because a reviewer found the hole it plugs. That
# is the wrong order, and this is the fix: rather than asking "did I think of
# every failure?", MEASURE which of the gate's outcomes this matrix actually
# executes, and fail when any is never reached.
#
# It was not a hypothetical gap. The first run of this sweep found SEVEN of the
# gate's thirty-nine outcome sites had never been exercised, including both git
# read-failure branches and the `+` wrong-commit submodule state — that last
# one because the fixtures wrote an untracked `.gitmodules` and `git submodule
# status` returned success with no rows, so the branch could have been deleted
# outright with the matrix still green.
#
# Tracing is injected through PYTHONPATH into the subprocesses the matrix
# spawns, so the gate keeps no test-only hook: tests use the production entry
# point exactly as CI does.
_COV = pathlib.Path(tempfile.mkdtemp(prefix="doc-claims-cov-"))
atexit.register(shutil.rmtree, _COV, True)
(_COV / "sitecustomize.py").write_text(
    "import atexit, os, sys, threading\n"
    "NAME = os.environ.get('COV_TARGET', '')\n"
    "OUT = os.environ.get('COV_OUT', '')\n"
    "hits = set()\n"
    "def tracer(frame, event, arg):\n"
    "    if event == 'line' and os.path.basename(frame.f_code.co_filename) == NAME:\n"
    "        hits.add(frame.f_lineno)\n"
    "    return tracer\n"
    "if NAME and OUT:\n"
    "    threading.settrace(tracer); sys.settrace(tracer)\n"
    "    @atexit.register\n"
    "    def _dump():\n"
    "        with open(OUT, 'a') as f:\n"
    "            f.writelines(f'{n}\\n' for n in sorted(hits))\n",
    encoding="utf-8")
_HITS = _COV / "hits.txt"

# ── depth safety ──────────────────────────────────────────────────────────────
# This repository was briefly SHALLOW today (one reachable commit), and a peer
# drew a false negative from it: a one-commit history answers "no earlier
# version exists" for everything, which is indistinguishable from the true
# answer and reads as a clean result.
#
# The gate is safe from that TODAY because every git call it makes reads a
# SINGLE named revision — `submodule status`, `rev-parse --verify`, `ls-tree`,
# `show` — and never walks history. That is not luck and it is not permanent:
# it is a property a future maintainer can remove in one line, and CI fetches
# the base with `--depth=1` on purpose, so a shallow clone is the NORMAL state
# here rather than the broken one.
#
# So the guard is an allowlist, not a shallow-check. Refusing to run in a
# shallow repository would be a false constraint that breaks this gate's own
# workflow; forbidding the operations that a shallow repository cannot answer
# is the constraint that actually matches the hazard.
# "status" reads the WORKING TREE, not history, so it is depth-safe — added
# when the dirty-submodule check introduced it, and the allowlist caught that
# addition on its first run rather than letting it through unexamined.
DEPTH_SAFE = {"submodule", "rev-parse", "ls-tree", "show", "config", "status"}


# Ancestry operators. An allowlisted subcommand can still walk history through
# its REVISION argument: `show HEAD~1:path` and `rev-parse HEAD^` are both
# "depth-safe" by name and both need a parent commit a shallow clone does not
# have. A guard that checks only the verb would stay green through exactly the
# change it exists to prevent.
ANCESTRY = ("~", "^", "..", "@{")

# `^{commit}` and `^{tree}` PEEL an object to a type. They are not history: the
# object is the one already named, and a shallow clone answers them fine. The
# gate's own `rev-parse --verify {ref}^{{commit}}` is exactly this, so a bare
# "does it contain ^" test would have reported the gate unsafe the moment the
# scan could see it — a guard whose first act on gaining sight is a false red.
PEEL = re.compile(r"\^\{[^}]*\}")


def _literal(node) -> str | None:
    """The static text of a string or f-string; substitutions become \x00.

    Every revision the gate passes is an f-string — `f"{ref}^{{commit}}"`,
    `f"{ref}:{rel(BASELINE)}"` — so a scan that reads only ast.Constant is
    blind to precisely the arguments it exists to inspect. The substituted
    parts are unknowable here and are replaced by a byte that matches no
    ancestry operator, which is the honest reading: this check constrains the
    syntax the author wrote, not the value a variable may hold.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant)
                       and isinstance(v.value, str) else "{…}"
                       for v in node.values)
    return None


def _walks_ancestry(strings: list[str]) -> str | None:
    for s in strings:
        if s.startswith("-"):
            continue
        if any(op in PEEL.sub("", s) for op in ANCESTRY):
            return s
    return None


def _subcommand(strings: list[str]) -> str | None:
    """The first non-flag token, which is the subcommand.

    A `-C <path>` pair contributes no literal for the path (it is an
    expression), so skipping flags is enough — there is no flag-value to
    mistake for a subcommand.
    """
    return next((s for s in strings if not s.startswith("-")), None)


def unsafe_git_calls() -> list[str]:
    """Git subcommands the gate invokes that a shallow clone cannot answer.

    Read from the SYNTAX TREE rather than from text. The regex version
    recognised only DOUBLE-QUOTED calls, so an equally valid `git('log')` or
    `['git', 'log']` was invisible and the guard would have reported an unsafe
    history walk as safe — a check that passes because of how the code is
    punctuated is not a check. It also had an off-by-one that hid the unflagged
    `["git", "log"]` form, which my own falsification missed by injecting the
    `-C` form that happens to survive it. Both classes disappear here: the AST
    does not know what quotes are, and multi-line calls parse identically.
    """
    found = []
    for node in ast.walk(ast.parse(GATE.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        f, a0 = node.func, node.args[0]
        # the local `git(...)` helper: its first argument IS the subcommand
        if isinstance(f, ast.Name) and f.id == "git":
            # the subcommand is always a plain literal; the REVISIONS are not
            consts = [a.value for a in node.args
                      if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            texts = [s for s in (_literal(a) for a in node.args) if s is not None]
            if consts:
                found.append(consts[0])
                rev = _walks_ancestry([s for s in texts if s != consts[0]])
                if rev:
                    found.append(f"{consts[0]} {rev}")
            continue
        # any call taking a literal argv sequence that starts with "git"
        if isinstance(a0, (ast.List, ast.Tuple)) and a0.elts:
            head = a0.elts[0]
            if not (isinstance(head, ast.Constant) and head.value == "git"):
                continue
            strings = [e.value for e in a0.elts[1:]
                       if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            texts = [s for s in (_literal(e) for e in a0.elts[1:]) if s is not None]
            sub = _subcommand(strings)
            if sub:
                found.append(sub)
                rev = _walks_ancestry([s for s in texts if s != sub])
                if rev:
                    found.append(f"{sub} {rev}")
    return sorted({s for s in found if s not in DEPTH_SAFE})

# Probes for the depth guard itself. It had no falsification case at all — it
# was only ever exercised by hand — and each hand probe found something the
# previous one had missed: the unflagged argv form, then single quotes, then
# f-strings. The gate's own revisions are ALL f-strings, so the guard was blind
# to precisely the arguments it exists to inspect while reporting them safe.
#
# The peel case is not optional. `^{commit}` is a type dereference rather than
# a walk, and the gate's own `rev-parse --verify` uses it — so a guard that
# gained sight without gaining that distinction would have gone red on clean
# code, which is the failure that gets a check deleted rather than fixed.
DEPTH_PROBES = [
    ("f-string ancestor",  'git("show", f"{ref}~1:docs/x")',                True),
    ("f-string parent",    'git("show", f"{ref}^:docs/x")',                 True),
    ("f-string range",     'git("diff", f"{a}..{b}")',                      True),
    ("single-quoted argv", "subprocess.run(['git', 'blame', 'f'])",         True),
    ("multiline argv",     'subprocess.run([\n    "git",\n    "log",\n])', True),
    ("type peel",          'git("rev-parse", "--verify", f"{ref}^{{commit}}")', False),
    ("plain f-string rev", 'git("show", f"{ref}:docs/x")',                  False),
]


def probe_depth_guard() -> list[str]:
    """Every probe must land on its stated side. Returns the failures."""
    global GATE
    src = GATE.read_text(encoding="utf-8")
    real, bad = GATE, []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="depth-probe-")) / GATE.name
    atexit.register(shutil.rmtree, tmp.parent, True)
    for name, snippet, expect_unsafe in DEPTH_PROBES:
        tmp.write_text(src + "\n\ndef _probe(ref='r', a='a', b='b'):\n    "
                       + snippet.replace("\n", "\n    ") + "\n", encoding="utf-8")
        GATE = tmp
        got = bool(unsafe_git_calls())
        if got != expect_unsafe:
            bad.append(f"{name}: expected "
                       f"{'unsafe' if expect_unsafe else 'safe'}, got "
                       f"{'unsafe' if got else 'safe'}")
    GATE = real
    return bad


# What counts as an outcome: a reported discrepancy, a stated non-coverage, or
# a refusal to run. If the gate grows one of these and no case reaches it, this
# matrix goes red on the next run rather than on the next review.
# An outcome REPORTS something, so its argument is a message. That is the
# referent test, and line-prefix matching cannot make it.
#
# Ported to a sibling gate, the prefix version did not find zero sites — it
# found exactly ONE, `sys.exit(main())`, the entry point, which is not an
# outcome at all. That is worse than matching nothing: zero is conspicuous and
# one looks like the instrument working, and every floor here tests a COUNT
# while a count cannot test the KIND of thing counted. So the sites are read
# from the syntax tree and required to carry a string-shaped argument, which
# `sys.exit(main())` does not.
OUTCOME_CALLS = {"errs", "errors", "NOTES"}
MIN_SITES = 20          # a detector that finds almost nothing has broken


def _is_message(node) -> bool:
    """A literal string, an f-string, or strings joined with +."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_message(node.left) or _is_message(node.right)
    if isinstance(node, ast.IfExp):
        return _is_message(node.body) or _is_message(node.orelse)
    return False


def outcome_sites() -> list[tuple[int, str]]:
    src = GATE.read_text(encoding="utf-8")
    lines = src.splitlines()
    out = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        f = node.func
        hit = (isinstance(f, ast.Attribute) and f.attr == "append"
               and isinstance(f.value, ast.Name) and f.value.id in OUTCOME_CALLS)
        hit = hit or (isinstance(f, ast.Attribute) and f.attr == "exit"
                      and isinstance(f.value, ast.Name) and f.value.id == "sys")
        if hit and _is_message(node.args[0]):
            out.append((node.lineno, lines[node.lineno - 1].strip()[:70]))
    return sorted(set(out))


def uncovered() -> list[tuple[int, str]]:
    hits = {int(l) for l in _HITS.read_text(encoding="utf-8").splitlines() if l.strip()} \
        if _HITS.exists() else set()
    return [(n, s) for n, s in outcome_sites() if n not in hits]


# A declaring document that satisfies every leg. Each case below breaks
# exactly one thing in it (or in the corpus around it).
GOOD = """# Synthetic subject

**Status:** test fixture.

<!-- claim-audit: series XX-W -->
<!-- claim-audit: range XX-W -->
<!-- claim-audit: sections -->
<!-- claim-audit: numbered -->
<!-- claim-audit: counts -->
<!-- claim-audit: citations -->

See §2 for the table. The cite is `src/thing.cpp:3`.

## 1. First

1. one
2. two
3. three

## 2. Second

**3 rows** follow:

| ID | Note |
| --- | --- |
| XX-W1 | a |
| XX-W2 | b |
| XX-W3 | c |
"""

RESTATER = "# Restater\n\nThe range XX-W1…XX-W3 is complete.\n"


def build(tmp: pathlib.Path, doc: str = GOOD, restater: str = RESTATER,
          baseline: str | None = None) -> None:
    (tmp / "scripts" / "ci").mkdir(parents=True, exist_ok=True)
    shutil.copy(GATE, tmp / "scripts" / "ci" / GATE.name)
    (tmp / "src").mkdir(parents=True, exist_ok=True)
    (tmp / "src" / "thing.cpp").write_text("a\nb\nc\nd\n", encoding="utf-8")
    docs = tmp / "docs"
    (docs / "ci").mkdir(parents=True, exist_ok=True)
    (docs / "ci" / "doc-claims-baseline.txt").write_text(
        baseline if baseline is not None else
        "dead-citations: 0\ndeclares: docs/subject.md citations,counts,numbered,range:XX-W,sections,series:XX-W\n",
        encoding="utf-8")
    for i in range(60):  # clear the corpus floor
        (docs / f"filler{i:02d}.md").write_text(f"# Filler {i}\n", encoding="utf-8")
    (docs / "subject.md").write_text(doc, encoding="utf-8")
    if restater is not None:
        (docs / "restater.md").write_text(restater, encoding="utf-8")
    # A resolvable base ref for every case. An unresolved ref is now FATAL —
    # a ratchet with no base is an absent ratchet, not a lenient one — so the
    # matrix has to model the normal state (base exists, and by default holds
    # the same baseline as the candidate) or every case would fail on that
    # axis instead of its own.
    commit(tmp, "base")


def commit(t: pathlib.Path, branch: str) -> None:
    """Commit the tree as `branch` (idempotent init, so hooks can add commits)."""
    if not (t / ".git").exists():
        subprocess.run(["git", "init", "-q", "-b", branch], cwd=t, check=True,
                       capture_output=True)
        for k, v in (("user.email", "matrix@example.invalid"),
                     ("user.name", "matrix")):
            subprocess.run(["git", "config", k, v], cwd=t, check=True,
                           capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=t, check=True, capture_output=True)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", branch,
                    "--allow-empty"], cwd=t, check=True, capture_output=True)


def run(tmp: pathlib.Path, env: dict | None = None) -> tuple[int, str]:
    e = dict(os.environ)
    e["PYTHONPATH"] = str(_COV) + os.pathsep + e.get("PYTHONPATH", "")
    e["COV_TARGET"], e["COV_OUT"] = GATE.name, str(_HITS)
    # The base ref defaults to origin/dev, which a temp tree does not have; an
    # unset value would leave every git-backed case silently unchecked.
    e["DOC_CLAIMS_BASE_REF"] = "base"
    e.update(env or {})
    r = subprocess.run([sys.executable, str(tmp / "scripts" / "ci" / GATE.name)],
                       capture_output=True, text=True, env=e)
    return r.returncode, (r.stdout + r.stderr)


def case(name: str, expect: str, doc: str = GOOD, restater: str = RESTATER,
         corpus=None, baseline: str | None = None,
         env: dict | None = None) -> tuple[str, bool, str]:
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        build(tmp, doc, restater, baseline)
        if corpus:
            corpus(tmp)
        rc, out = run(tmp, env)
        line = next((l.strip() for l in out.splitlines()
                     if expect.lower() in l.lower()), "")
        return name, (rc != 0 and bool(line)), (line or out.splitlines()[0][:90])


def green(name: str, doc: str = GOOD, restater: str = RESTATER,
          extra=None, baseline: str | None = None, env: dict | None = None,
          expect: str | None = None) -> tuple[str, bool, str]:
    """A negative control: the gate must PASS here.

    A check that cannot distinguish its subject from a lookalike is as useless
    as one that cannot fail. The records-was exclusion is exactly that kind of
    distinction, so it needs a case proving the exclusion excludes — otherwise
    "no error" could mean the leg simply never ran.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        build(tmp, doc, restater, baseline)
        if extra:
            extra(tmp)
        rc, out = run(tmp, env)
        # A control may also have to prove the gate SAID something — a stated
        # non-coverage passes the run, so exit status alone cannot distinguish
        # "reported it" from "never noticed".
        line = next((l.strip() for l in out.splitlines()
                     if expect and expect.lower() in l.lower()), "")
        ok = rc == 0 and (not expect or bool(line))
        return name, ok, (line or (out.strip().splitlines()[0][:86]
                                   if out.strip() else ""))


def with_submodule(populated: bool, gitlink: bool = False):
    """Give the synthetic tree a .gitmodules and an external/sub, or not.

    The distinction under test is between a file that was DELETED and one that
    is merely not checked out. Both look identical to `is_file()`, which is how
    the real baseline shipped one too high, so the matrix has to exercise a
    populated submodule and an empty one against the same citation.
    """
    def f(t: pathlib.Path) -> None:
        (t / ".gitmodules").write_text(
            '[submodule "external/sub"]\n\tpath = external/sub\n'
            "\turl = https://example.invalid/sub.git\n", encoding="utf-8")
        d = t / "external" / "sub"
        d.mkdir(parents=True, exist_ok=True)
        if populated:
            (d / "inc.h").write_text("one\ntwo\nthree\n", encoding="utf-8")
        elif gitlink:
            # What an interrupted `submodule update` leaves: the gitlink is
            # written before any content arrives, so the directory is non-empty
            # while holding none of the files a citation could resolve against.
            (d / ".git").write_text("gitdir: ../../.git/modules/external/sub\n",
                                    encoding="utf-8")
    return f


# A document holding TWO declarations of the SAME KIND. This is the fixture that
# distinguishes a registry keyed on `kind` from one keyed on the full
# declaration: with only the kind recorded, dropping `series YY-Q` leaves
# `series` still present via XX-W and the drop goes unnoticed.
TWO_SERIES = GOOD + """
## 3. Third

| ID | Note |
| --- | --- |
| YY-Q1 | a |
| YY-Q2 | b |
"""
TWO_SERIES = TWO_SERIES.replace("<!-- claim-audit: series XX-W -->",
                                "<!-- claim-audit: series XX-W -->\n"
                                "<!-- claim-audit: series YY-Q -->")
TWO_SERIES_LEGS = ("citations,counts,numbered,range:XX-W,sections,"
                   "series:XX-W,series:YY-Q")


def git_base(base_dead: int):
    """Commit a base revision whose baseline carries `base_dead`.

    The ratchet asserts against a figure that travels in the same commit as the
    change being asserted, so without a base revision one edit can add rot and
    lift the bar to match. Exercising that needs a real git history, so the
    matrix builds one in the temp tree — still touching nothing in the repo.
    """
    def f(t: pathlib.Path) -> None:
        bl = t / "docs" / "ci" / "doc-claims-baseline.txt"
        candidate = bl.read_text(encoding="utf-8")
        bl.write_text(re.sub(r"dead-citations: \d+",
                             f"dead-citations: {base_dead}", candidate),
                      encoding="utf-8")
        commit(t, "base")
        bl.write_text(candidate, encoding="utf-8")   # restore the candidate
    return f


# A second declaring document, so a control that deletes the first does not
# simply trip the adoption floor instead. The first attempt at that control did
# exactly this and reported the floor's message — a case failing for the wrong
# reason is a case testing nothing.
MINI = ("# Mini\n\n<!-- claim-audit: sections -->\n\nSee §1 below.\n\n"
        "## 1. One\n\nBody.\n")


def git_base_text(text: str):
    """Commit a base revision whose baseline file holds exactly `text`."""
    def f(t: pathlib.Path) -> None:
        bl = t / "docs" / "ci" / "doc-claims-baseline.txt"
        candidate = bl.read_text(encoding="utf-8")
        bl.write_text(text, encoding="utf-8")
        commit(t, "base")
        bl.write_text(candidate, encoding="utf-8")
    return f


def rot(n: int):
    """Add `n` dead citations in a NON-declaring document.

    Kept out of the declaring document on purpose: the ratchet is what is under
    test, and routing the rot through a declared `citations` leg would make the
    case fire on that leg's axis instead.
    """
    def f(t: pathlib.Path) -> None:
        body = "\n".join(f"- see `src/gone{i}.cpp:1`" for i in range(n))
        (t / "docs" / "rot.md").write_text(f"# Rot\n\n{body}\n", encoding="utf-8")
    return f


def chain(*fns):
    def f(t: pathlib.Path) -> None:
        for fn in fns:
            fn(t)
    return f


# A nested list: the shape the column-0 matcher was blind to. The children are
# indented, so they never matched; the blank line after them then closed the
# outer fragment, which fell under the three-item floor and was discarded. Both
# levels have to be checkable, or the leg reports a tally for structure it
# never looked at.
NESTED = GOOD.replace("""1. one
2. two
3. three""", """1. one
2. two
   1. child a
   2. child b
   3. child c
3. three""")


def real_submodule(state: str):
    """A REAL gitlink, so `git submodule status` actually reports -, + or clean.

    The previous fixture wrote an untracked `.gitmodules` beside an ordinary
    directory. `git submodule status` then returned success with NO rows, so
    the production branch that reads its "-", "+" and "U" flags was never
    executed by any case — the matrix reported dozens of green paths while that
    branch had zero coverage, and deleting it outright would not have turned
    anything red. A falsification matrix that cannot fail when a branch is
    removed is not covering that branch.

    Each recipe below was verified by hand before being written here: a gitlink
    with no config entry reports "-" whatever the directory holds, and "+"
    requires BOTH an initialised config entry and a HEAD other than the
    recorded commit.
    """
    def f(t: pathlib.Path) -> None:
        d = t / "external" / "sub"
        d.mkdir(parents=True, exist_ok=True)
        g = lambda *a, **k: subprocess.run(list(a), cwd=k.get("cwd", d),
                                           check=True, capture_output=True,
                                           text=True)
        g("git", "init", "-q", "-b", "main", ".")
        g("git", "config", "user.email", "matrix@example.invalid")
        g("git", "config", "user.name", "matrix")
        (d / "inc.h").write_text("one\ntwo\nthree\n", encoding="utf-8")
        g("git", "add", "-A")
        g("git", "-c", "commit.gpgsign=false", "commit", "-qm", "sub")
        recorded = g("git", "rev-parse", "HEAD").stdout.strip()
        if state == "wrong_commit":
            # move the submodule's HEAD past the commit the gitlink records
            (d / "inc.h").write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
            g("git", "add", "-A")
            g("git", "-c", "commit.gpgsign=false", "commit", "-qm", "moved")
        (t / ".gitmodules").write_text(
            '[submodule "external/sub"]\n\tpath = external/sub\n'
            "\turl = ./external/sub\n", encoding="utf-8")
        g("git", "update-index", "--add", "--cacheinfo",
          f"160000,{recorded},external/sub", cwd=t)
        # "-" is reported for an UNINITIALISED submodule regardless of content,
        # so the config entry is what makes the "+" case reachable at all.
        if state != "missing":
            g("git", "config", "submodule.external/sub.url", "./external/sub",
              cwd=t)
        if state == "missing":
            shutil.rmtree(d)
            d.mkdir(parents=True)
        if state == "dirty":
            # HEAD still matches the gitlink, so `git submodule status` reports
            # CLEAN — verified directly. Only a worktree check sees this.
            (d / "inc.h").write_text("one\ntwo\nthree\nEDITED\n", encoding="utf-8")
    return f


def no_git_repo(t: pathlib.Path) -> None:
    """A tree with submodules declared but no git to report on them."""
    (t / ".gitmodules").write_text(
        '[submodule "external/sub"]\n\tpath = external/sub\n'
        "\turl = ./external/sub\n", encoding="utf-8")
    shutil.rmtree(t / ".git")


def drop_object(kind: str):
    """Delete a git object so a specific read fails while others still succeed.

    Verified by hand before use: with the BLOB gone, `ls-tree` still succeeds
    and `git show` fails; with the root TREE gone as well, the commit still
    resolves and `ls-tree` fails. That is precisely the pair of states the gate
    must not collapse into "bootstrap", so the matrix has to be able to build
    both.
    """
    def f(t: pathlib.Path) -> None:
        def rev(spec):
            return subprocess.run(["git", "rev-parse", spec], cwd=t, check=True,
                                  capture_output=True, text=True).stdout.strip()
        objs = [rev("base:docs/ci/doc-claims-baseline.txt")]
        if kind == "tree":
            objs.append(rev("base^{tree}"))
        for o in objs:
            (t / ".git" / "objects" / o[:2] / o[2:]).unlink(missing_ok=True)
    return f


def sub(old: str, new: str) -> str:
    assert GOOD.count(old) == 1, f"fixture anchor not unique: {old!r}"
    return GOOD.replace(old, new)


def main() -> None:
    cases = [
        # corpus- and adoption-level subject assertion
        case("corpus floor (docs emptied)", "corpus this gate audits",
             corpus=lambda t: [p.unlink() for p in (t / "docs").glob("*.md")]),
        case("no declarations anywhere", "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit:", "<!-- was-claim-audit:")),
        case("unknown declaration kind", "unknown claim-audit kind",
             doc=sub("<!-- claim-audit: sections -->", "<!-- claim-audit: rationale -->")),
        # series
        case("series: duplicate row", "duplicate rows",
             doc=sub("| XX-W3 | c |", "| XX-W2 | c |")),
        case("series: gap", "missing [2]",
             doc=sub("| XX-W2 | b |", "| XX-W4 | b |")),
        case("series: subject missing", "the subject this declaration names is missing",
             doc=sub("<!-- claim-audit: series XX-W -->", "<!-- claim-audit: series ZZ-Q -->")),
        case("series: no prefix given", "needs a prefix",
             doc=sub("<!-- claim-audit: series XX-W -->", "<!-- claim-audit: series -->")),
        # range
        case("range: restatement disagrees", "restates the XX-W range as",
             restater="# Restater\n\nThe range XX-W1…XX-W2 is complete.\n"),
        case("range: nothing restates it", "no document restates that range",
             restater=None),
        # sections
        case("sections: dangling reference", "which this document does not have",
             doc=sub("See §2 for the table.", "See §7 for the table.")),
        # Both numbered headings must go: removing one leaves §2 resolvable, so
        # the leg passes correctly and the case would be testing nothing. The
        # first attempt at this case did exactly that and reported a false green
        # for the matrix rather than for the gate.
        case("sections: no numbered headings", "has no numbered headings",
             doc=GOOD.replace("## 1. First", "## First").replace("## 2. Second", "## Second")),
        # numbered
        case("numbered: gap in the list", "numbered list runs",
             doc=sub("2. two", "3. two")),
        case("numbered: no list at all", "no numbered list of two",
             doc=sub("1. one\n2. two\n3. three", "- one\n- two\n- three")),
        # counts
        case("counts: figure disagrees with table", "over a table of",
             doc=sub("**3 rows** follow", "**4 rows** follow")),
        case("counts: no figure stated", "states no **N rows** figure",
             doc=sub("**3 rows** follow:", "The rows follow:")),
        # code-fence immunity: documenting the syntax must not declare it, and
        # the negative case matters as much as the positive — a fenced example
        # that still counted is how this gate first failed against its own
        # README section.
        case("declaration inside a fence is not one", "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "```\n<!-- claim-audit: series XX-W -->\n```")
                     .replace("<!-- claim-audit: range XX-W -->", "")
                     .replace("<!-- claim-audit: sections -->", "")
                     .replace("<!-- claim-audit: numbered -->", "")
                     .replace("<!-- claim-audit: counts -->", "")
                     .replace("<!-- claim-audit: citations -->", "")),
        # citations
        case("citations: file does not exist", "which does not exist",
             doc=sub("`src/thing.cpp:3`", "`src/absent.cpp:3`")),
        case("citations: line beyond end of file", "but that file has",
             doc=sub("`src/thing.cpp:3`", "`src/thing.cpp:99`")),
        case("citations: none present", "declares `citations` but makes none",
             doc=sub("The cite is `src/thing.cpp:3`.", "No cite here.")),
        # submodule discrimination — the defect this PR shipped and CI caught.
        # A path inside a submodule that is not checked out must STOP the run,
        # because a count taken against files that are merely absent locally
        # disagrees with CI by environment rather than by fact.
        case("citation into an uninitialised submodule", "not checked out here",
             doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
             corpus=with_submodule(populated=False)),
        # ...and the branch must discriminate by PATH, not merely notice that
        # some submodule is empty. Same empty submodule, a dead citation that
        # has nothing to do with it: still ordinary rot, still reported as rot.
        case("dead citation elsewhere is still rot", "which does not exist",
             doc=sub("`src/thing.cpp:3`", "`src/absent.cpp:3`"),
             corpus=with_submodule(populated=False)),
        # A bare .git gitlink is not content: an interrupted update leaves the
        # directory non-empty and holding nothing a citation resolves against,
        # so a naive "is it empty" test would call the whole tree deleted.
        case("submodule holding only a gitlink", "not checked out here",
             doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
             corpus=with_submodule(populated=False, gitlink=True)),
        # ratchet — opt-in without one is adoption theatre, so each direction
        # of the ratchet has to be able to bite.
        case("ratchet: dead citations rose", "rose to",
             doc=sub("`src/thing.cpp:3`", "`src/gone.cpp:3`")),
        case("ratchet: baseline left above the truth", "lower the `dead-citations:`",
             baseline="dead-citations: 4\ndeclares: docs/subject.md citations,counts,numbered,range:XX-W,sections,series:XX-W\n"),
        case("ratchet: a declared leg was dropped", "has dropped the claim-audit",
             doc=sub("<!-- claim-audit: counts -->", "")),
        # negative control: a stale range inside a records-was surface is
        # history, not a live claim, and must NOT fail the gate — otherwise a
        # register growing forces edits to closed round records.
        green("historical restatement is not a live claim",
              extra=lambda t: ((t / "docs" / "completed").mkdir(exist_ok=True),
                               (t / "docs" / "completed" / "old.md").write_text(
                                   "# Closed round\n\nIt held XX-W1…XX-W2 then.\n",
                                   encoding="utf-8"))),
        # negative control: a POPULATED submodule is ordinary tree, and its
        # citations resolve. Without this, "skip everything under a submodule"
        # would pass the matrix while silently retiring the leg for external/.
        green("populated submodule resolves normally",
              doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
              extra=with_submodule(populated=True)),
        # range: the LOWER endpoint is half the claim. Matching only the upper
        # one let a restatement say the series starts where it does not.
        case("range: wrong lower endpoint", "restates the XX-W range as",
             restater="# Restater\n\nThe range XX-W2…XX-W3 is complete.\n"),
        # declaration identity — a registry keyed on kind alone cannot tell
        # which of two same-kind declarations it is holding.
        case("one of two same-kind declarations dropped", "series:YY-Q",
             doc=TWO_SERIES.replace("<!-- claim-audit: series YY-Q -->\n", ""),
             baseline=f"dead-citations: 0\ndeclares: docs/subject.md {TWO_SERIES_LEGS}\n"),
        # ...and the registry must be COMPLETE, or a leg added after it was
        # written can be removed later with nothing to notice.
        case("declaration absent from the registry", "does not record it as holding",
             doc=TWO_SERIES,
             baseline="dead-citations: 0\ndeclares: docs/subject.md "
                      "citations,counts,numbered,range:XX-W,sections,series:XX-W\n"),
        # the ratchet's own bar: a change that adds rot AND lifts the baseline
        # to match passes every single-tree check, because the bar travels in
        # the same commit as the change it is supposed to constrain.
        case("ratchet: baseline raised against the base revision", "was RAISED from",
             baseline="dead-citations: 3\ndeclares: docs/subject.md "
                      "citations,counts,numbered,range:XX-W,sections,series:XX-W\n",
             corpus=chain(git_base(0), rot(3)),
             env={"DOC_CLAIMS_BASE_REF": "base"}),
        green("lowering the baseline against the base revision is allowed",
              baseline="dead-citations: 0\ndeclares: docs/subject.md "
                       "citations,counts,numbered,range:XX-W,sections,series:XX-W\n",
              extra=git_base(3), env={"DOC_CLAIMS_BASE_REF": "base"}),
        # the registry line is a reference value too: dropping a declaration
        # AND deleting the token recording it passes every single-tree check.
        case("registry line shrunk against the base revision", "was SHRUNK against",
             doc=TWO_SERIES.replace("<!-- claim-audit: series YY-Q -->\n", ""),
             baseline="dead-citations: 0\ndeclares: docs/subject.md "
                      "citations,counts,numbered,range:XX-W,sections,series:XX-W\n",
             corpus=git_base_text("dead-citations: 0\ndeclares: docs/subject.md "
                                  f"{TWO_SERIES_LEGS}\n"),
             env={"DOC_CLAIMS_BASE_REF": "base"}),
        green("deleting a document releases its registry line",
              extra=chain(
                  git_base_text("dead-citations: 0\n"
                                f"declares: docs/subject.md {TWO_SERIES_LEGS}\n"
                                "declares: docs/mini.md sections\n"),
                  lambda t: (t / "docs" / "subject.md").unlink(),
                  lambda t: (t / "docs" / "mini.md").write_text(MINI,
                                                                encoding="utf-8")),
              baseline="dead-citations: 0\ndeclares: docs/mini.md sections\n",
              env={"DOC_CLAIMS_BASE_REF": "base"}),
        # malformed markers: a typo reads as opted-in to a human and as absent
        # to a strict-only matcher, and the adoption floor stays satisfied by
        # some other document, so nothing anywhere goes red.
        case("malformed marker (wrong case)", "malformed claim-audit marker",
             doc=GOOD.replace("<!-- claim-audit: counts -->",
                              "<!-- claim-audit: Counts -->")),
        case("malformed marker (two arguments)", "malformed claim-audit marker",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "<!-- claim-audit: series XX-W extra -->")),
        # nested lists — both levels must be checkable
        case("numbered: gap in a NESTED list", "numbered list runs",
             doc=NESTED.replace("   2. child b", "   3. child b")),
        case("numbered: gap in the list AROUND a nested one", "numbered list runs",
             doc=NESTED.replace("3. three", "4. three")),
        # a count claim whose table vanished is a missing subject, not a claim
        # that needs no checking
        case("counts: a second claim lost its table", "no table with data rows",
             doc=GOOD.replace("| XX-W3 | c |",
                              "| XX-W3 | c |\n\n**2 rows** follow:\n")),
        # an unresolved base ref disables BOTH base-backed ratchets, so it is
        # fatal rather than skipped (rule 47: assert the prerequisite).
        case("base ref does not resolve", "does not resolve",
             env={"DOC_CLAIMS_BASE_REF": "__no_such_ref__"}),
        case("established baseline is unparseable", "states no `dead-citations:`",
             corpus=git_base_text("declares: docs/subject.md sections\n"),
             env={"DOC_CLAIMS_BASE_REF": "base"}),
        # citation bounds: line numbers are one-based, and a range is a claim
        # about its whole span rather than just where it starts.
        case("citations: line zero", "line numbers start at 1",
             doc=sub("`src/thing.cpp:3`", "`src/thing.cpp:0`")),
        case("citations: range end past EOF", "the range's end",
             doc=sub("`src/thing.cpp:3`", "`src/thing.cpp:2-99`")),
        case("citations: range ends before it starts", "ends (2) before it starts",
             doc=sub("`src/thing.cpp:3`", "`src/thing.cpp:3-2`")),
        # numbered lists start at 1 — the invariant the marker documents
        case("numbered: run does not start at 1", "numbered list runs",
             doc=GOOD.replace("1. one\n2. two\n3. three",
                              "2. one\n3. two\n4. three")),
        # a repeated `1.` at the same indent is a mis-numbered list, not a new
        # one — CommonMark continues an ordered list across a repeated number.
        case("numbered: list restarts mid-run", "numbered list runs",
             doc=GOOD.replace("1. one\n2. two\n3. three",
                              "1. one\n2. two\n1. three\n2. four\n3. five")),
        # a count claim must bind to ITS table, not the next one anywhere below
        case("counts: table deleted, later table below", "no table with data rows",
             doc=GOOD.replace("""**3 rows** follow:

| ID | Note |
| --- | --- |
| XX-W1 | a |
| XX-W2 | b |
| XX-W3 | c |""", """**3 rows** follow:

## 3. Elsewhere

| ID | Note |
| --- | --- |
| XX-W1 | a |
| XX-W2 | b |
| XX-W3 | c |""")),
        # a citation must not escape the repository
        case("citations: path escapes the tree", "which does not exist",
             doc=sub("`src/thing.cpp:3`", "`src/../../etc/thing.py:1`")),
        # records-was must match path components, not substrings: a live
        # document must not be excused from the gate by its NAME.
        case("records-was lookalike is still live", "rose to",
             corpus=lambda t: (t / "docs" / "FOO_CHANGELOG.md").write_text(
                 "# Lookalike\n\nSee `src/gone.cpp:1`.\n", encoding="utf-8")),
        # REAL gitlinks: these are the cases that actually execute the
        # -, + and clean branches of `git submodule status`.
        case("submodule gitlink not checked out (git reports -)", "not checked out here",
             doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
             corpus=real_submodule("missing")),
        case("submodule at the WRONG commit (git reports +)", "not checked out here",
             doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
             corpus=real_submodule("wrong_commit")),
        case("submodules declared but git cannot report", "could not be read",
             corpus=no_git_repo),
        green("submodule at the recorded commit resolves normally",
              doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
              extra=real_submodule("ok")),
        # --- sites the coverage sweep found unexercised ---
        case("range: no prefix given", "`claim-audit: range` needs a prefix",
             doc=sub("<!-- claim-audit: range XX-W -->", "<!-- claim-audit: range -->"),
             baseline="dead-citations: 0\ndeclares: docs/subject.md "
                      "citations,counts,numbered,range,sections,series:XX-W\n"),
        case("range: declaring doc owns no rows", "owns no",
             doc=sub("<!-- claim-audit: range XX-W -->", "<!-- claim-audit: range ZZ-Q -->"),
             baseline="dead-citations: 0\ndeclares: docs/subject.md "
                      "citations,counts,numbered,range:ZZ-Q,sections,series:XX-W\n"),
        case("sections: declared but no §N reference", "makes no §N reference",
             doc=sub("See §2 for the table. ", "")),
        case("local baseline states no figure", "states no `dead-citations:` figure",
             baseline=f"declares: docs/subject.md citations,counts,numbered,range:XX-W,sections,series:XX-W\n"),
        case("git itself cannot run", "git could not run",
             env={"PATH": ""}),
        case("base tree unreadable", "could not list",
             corpus=drop_object("tree"), env={"DOC_CLAIMS_BASE_REF": "base"}),
        case("base baseline present but unreadable", "could not be read",
             corpus=drop_object("blob"), env={"DOC_CLAIMS_BASE_REF": "base"}),
        # a stated non-coverage: the gate PASSES and says what it declined,
        # because "checked and passed" and "not looked at" must not look alike.
        green("dotted §N.M is reported as not checked, not failed",
              doc=sub("See §2 for the table.", "See §2 for the table. Also DRS §6.6."),
              expect="dotted §N.M reference"),
        case("submodule worktree is DIRTY (status still reports clean)",
             "not checked out here",
             doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
             corpus=real_submodule("dirty")),
        # CommonMark code forms strip_code must also blank: a marker surviving
        # either would opt a document into checks it never asked for.
        case("marker inside a TILDE fence is not a declaration", "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "~~~\n<!-- claim-audit: series XX-W -->\n~~~")
                     .replace("<!-- claim-audit: range XX-W -->", "")
                     .replace("<!-- claim-audit: sections -->", "")
                     .replace("<!-- claim-audit: numbered -->", "")
                     .replace("<!-- claim-audit: counts -->", "")
                     .replace("<!-- claim-audit: citations -->", "")),
        case("marker inside a DOUBLE-BACKTICK span is not a declaration",
             "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "``<!-- claim-audit: series XX-W -->``")
                     .replace("<!-- claim-audit: range XX-W -->", "")
                     .replace("<!-- claim-audit: sections -->", "")
                     .replace("<!-- claim-audit: numbered -->", "")
                     .replace("<!-- claim-audit: counts -->", "")
                     .replace("<!-- claim-audit: citations -->", "")),
        # CommonMark: a CLOSING fence carries its delimiter and nothing else.
        # Treating an info string as a close ended the block early and exposed
        # the examples below it as real declarations.
        case("info string does not close a fence", "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "```\n```python\n<!-- claim-audit: series XX-W -->\n```")
                     .replace("<!-- claim-audit: range XX-W -->", "")
                     .replace("<!-- claim-audit: sections -->", "")
                     .replace("<!-- claim-audit: numbered -->", "")
                     .replace("<!-- claim-audit: counts -->", "")
                     .replace("<!-- claim-audit: citations -->", "")),
        # code spans may cross line breaks, and a per-line pass missed those
        case("marker inside a MULTILINE span is not a declaration",
             "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "``example\n<!-- claim-audit: series XX-W -->\nend``")
                     .replace("<!-- claim-audit: range XX-W -->", "")
                     .replace("<!-- claim-audit: sections -->", "")
                     .replace("<!-- claim-audit: numbered -->", "")
                     .replace("<!-- claim-audit: counts -->", "")
                     .replace("<!-- claim-audit: citations -->", "")),
        # An EXAMPLE of a defect is not a defect. Before this, structural legs
        # read raw markdown: a fenced 1./3. list failed `numbered`, fenced
        # register rows entered `series`, and a fenced range became a live
        # restatement. All three appear together here and must be ignored.
        green("fenced examples are not document structure",
              doc=GOOD + "\n\n```\n1. one\n3. three\n5. five\n```\n\n```\n| ID | Note |\n| --- | --- |\n| XX-W9 | fake |\n```\n\n```\nThe range XX-W1…XX-W99 is complete.\n```\n"),
        # a marker inside a 4-space INDENTED code block is an example
        case("marker in an indented code block is not a declaration",
             "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "Example:\n\n    <!-- claim-audit: series XX-W -->")
                     .replace("<!-- claim-audit: range XX-W -->", "")
                     .replace("<!-- claim-audit: sections -->", "")
                     .replace("<!-- claim-audit: numbered -->", "")
                     .replace("<!-- claim-audit: counts -->", "")
                     .replace("<!-- claim-audit: citations -->", "")),
        # §9. at the end of a sentence is a reference; only §9.1 is a subsection
        case("sections: punctuated reference is still checked",
             "which this document does not have",
             doc=sub("See §2 for the table.", "See §7.")),
        # a dead citation inside a fence is an EXAMPLE, not a claim — for the
        # declared leg and for the corpus-wide ratchet alike.
        green("dead citation inside a fence is not a citation",
              doc=GOOD + "\n\n```\nsee `src/gone.cpp:9999` for the shape\n```\n",
              extra=lambda t: (t / "docs" / "example.md").write_text(
                  "# Example\n\n```\ncite `src/also-gone.cpp:1` here\n```\n",
                  encoding="utf-8")),
        # an indented fence opener must not blank the rest of the document
        green("deeply indented ``` does not open a fence",
              doc=GOOD.replace("## 2. Second",
                               "- item\n\n      ```\n\n## 2. Second")),
        case("ratchet: baseline file missing", "has no baseline",
             corpus=lambda t: (t / "docs" / "ci" / "doc-claims-baseline.txt").unlink()),
    ]

    # Green negative controls are marked so the tally cannot claim a control
    # as a failure path — a matrix that miscounts its own cases is the first
    # thing a reader stops trusting.
    controls = {"historical restatement is not a live claim",
                "populated submodule resolves normally",
                "lowering the baseline against the base revision is allowed",
                "deleting a document releases its registry line",
                "submodule at the recorded commit resolves normally",
                "dotted §N.M is reported as not checked, not failed",
                "fenced examples are not document structure",
                "dead citation inside a fence is not a citation",
                "deeply indented ``` does not open a fence"}
    print(f"{'CASE':<44} {'AS EXPECTED':<12} message")
    for name, ok, msg in cases:
        kind = "green" if name in controls else "red"
        print(f"{name:<44} {('yes' if ok else 'NO') + f' ({kind})':<12} {msg[:74]}")
    bad = [n for n, ok, _ in cases if not ok]
    n_red = len([c for c in cases if c[0] not in controls])
    n_green = len(cases) - n_red

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        build(tmp)
        rc, out = run(tmp)
    clean_ok = rc == 0 and "does not check rationales" in out
    print(f"\nclean synthetic tree: {'GREEN' if clean_ok else 'NOT GREEN'} — "
          f"{out.strip().splitlines()[0][:80] if out.strip() else '(no output)'}")

    # The sweep, after every case has run: an outcome the matrix never reaches
    # is an outcome nobody has shown can happen, and a green here would be
    # counting cases rather than covering the gate.
    gaps = uncovered()
    sites = outcome_sites()
    if len(sites) < MIN_SITES:
        sys.exit(f"FAIL: the outcome detector found only {len(sites)} site(s) "
                 f"(floor {MIN_SITES}). Full coverage of almost nothing is the "
                 "failure this floor exists to catch — a count cannot tell you "
                 "WHAT it counted.")
    unsafe = unsafe_git_calls()
    probe_fails = probe_depth_guard()
    print(f"depth guard probes: {len(DEPTH_PROBES) - len(probe_fails)}/"
          f"{len(DEPTH_PROBES)} landed on the expected side"
          + ("" if not probe_fails else f" — {probe_fails}"))
    print(f"depth safety: git subcommands used are "
          + (", ".join(sorted(DEPTH_SAFE)) if not unsafe
             else f"UNSAFE — {unsafe}"))
    print(f"\noutcome coverage: {len(sites) - len(gaps)}/{len(sites)} of the "
          "gate's discrepancy, non-coverage and refusal sites were executed")
    for n, s in gaps:
        print(f"  NEVER REACHED  {GATE.name}:{n}: {s}")

    if bad or not clean_ok or gaps or unsafe or probe_fails:
        sys.exit(
            (f"FAIL: {len(bad)} path(s) did not fire on their own axis: {bad}\n"
             if bad else "FAIL:\n")
            + ("" if clean_ok else "  the clean tree did not pass\n")
            + (f"  {len(gaps)} outcome site(s) are never reached by any case — "
               "add a case or delete the branch; an outcome with no case is a "
               "claim nobody has shown can happen\n" if gaps else "")
            + (f"  the depth guard mis-classified: {probe_fails}\n"
               if probe_fails else "")
            + (f"  the gate now uses history-walking git subcommand(s) {unsafe}. "
               "CI fetches the base with --depth=1, so a shallow clone is the "
               "NORMAL state here: a history walk would return a clean-looking "
               "answer computed from one commit. Either keep to single-revision "
               "reads, or make the gate refuse to run when the repository is "
               "shallow.\n" if unsafe else ""))
    print(f"\nOK: {n_red} failure paths each fired on its own axis, {n_green} "
          "negative control(s) stayed green, and the clean tree passes.")


if __name__ == "__main__":
    main()
