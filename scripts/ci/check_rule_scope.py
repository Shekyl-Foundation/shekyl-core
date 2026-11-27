#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every rule loads, belongs to its series, and attaches where it says.

The Shekyl repositories share the estate rules (00-99, canonical in shekyl-core,
copied verbatim into shekyl-gui-wallet and shekyl-prism) and each keeps its own
series: core 101-199, GUI 201-299, prism 901-999 (ruled 2026-11-19, Round 0
§7). An estate rule's frontmatter says which repositories it governs
(`repos:`); its globs are the union of its paths across them, so in a
repository that lacks a path the glob matches nothing and the file stays
verbatim. Cursor reads only `description`, `globs`, `alwaysApply` and `name`
(3.32.4), so the `scope` and `repos` keys are this gate's.

Run in each repository with its own name. It fails when:

  - a rule's frontmatter is missing or does not parse (Cursor drops such a
    file without a word), or has no description or no scope;
  - a rule's number is outside its scope's series, or a repository carries
    another repository's series;
  - an always-applied estate rule does not list every repository (it
    attaches in all of them);
  - a glob-scoped estate rule lists this repository and matches no tracked
    file here, or does not list it and matches one (it would attach where it
    says it does not apply);
  - an estate rule links relatively outside `.cursor/rules/`, or to a
    repository's own rule, either of which dangles in a copy. A fragment
    or query on that link is stripped before the target is judged.

Globs are matched as Cursor matches them: minimatch with `dot: true`, against
the path relative to the repository root.

Usage:
  check_rule_scope.py --repo core            check this checkout
  check_rule_scope.py --repo core --selftest plant each defect and require a failure
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

import yaml

REPOS = ("core", "gui", "prism")
SERIES = {"estate": range(0, 100), "core": range(101, 200), "gui": range(201, 300), "prism": range(901, 1000)}
RULES = ".cursor/rules"
MIN_RULES = 5


def glob_regex(pattern: str) -> re.Pattern:
    """minimatch semantics for the forms the rules use: **, *, ?."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def as_list(globs) -> list[str]:
    if globs is None:
        return []
    if isinstance(globs, str):
        return [g.strip() for g in globs.split(",") if g.strip()]
    return [str(g) for g in globs]


def frontmatter(text: str):
    if not text.startswith("---\n"):
        return None, "no frontmatter"
    end = text.find("\n---\n", 4)
    if end < 0:
        return None, "frontmatter is not closed"
    try:
        fm = yaml.safe_load(text[4:end])
    except yaml.YAMLError as e:
        return None, f"frontmatter does not parse: {str(e).splitlines()[0]}"
    if not isinstance(fm, dict):
        return None, "frontmatter is not a mapping"
    return fm, None


def tracked(root: str) -> list[str]:
    out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True).stdout
    return [f for f in out.split("\n") if f]


def check(root: str, repo: str) -> int:
    rules_dir = os.path.join(root, RULES)
    names = sorted(f for f in os.listdir(rules_dir) if f.endswith((".mdc", ".md"))) if os.path.isdir(rules_dir) else []
    if len(names) < MIN_RULES:
        print(f"FAIL: {len(names)} rule files under {RULES}; expected at least {MIN_RULES}")
        return 1
    files = tracked(root)
    fails: list[str] = []
    estate_names = set()
    parsed = {}
    for name in names:
        with open(os.path.join(rules_dir, name), encoding="utf-8") as fh:
            text = fh.read()
        fm, err = frontmatter(text)
        if err:
            fails.append(f"{name}: {err}")
            continue
        parsed[name] = (fm, text)
        if fm.get("scope") == "estate":
            estate_names.add(name[:-4] if name.endswith(".mdc") else name[:-3])
    for name, (fm, text) in parsed.items():
        where = f"{RULES}/{name}"
        scope = fm.get("scope")
        if not isinstance(fm.get("description"), str) or not fm["description"].strip():
            fails.append(f"{where}: no description")
        if scope not in SERIES:
            fails.append(f"{where}: scope {scope!r} is not one of {', '.join(SERIES)}")
            continue
        m = re.match(r"(\d+)-", name)
        if not m or int(m.group(1)) not in SERIES[scope]:
            fails.append(f"{where}: number outside the {scope} series")
        if scope not in ("estate", repo):
            fails.append(f"{where}: a {scope} rule in the {repo} repository")
        if "alwaysApply" in fm and not isinstance(fm["alwaysApply"], bool):
            fails.append(f"{where}: alwaysApply is not a boolean")
        if scope != "estate":
            continue
        repos = fm.get("repos")
        if not isinstance(repos, list) or not repos or any(r not in REPOS for r in repos):
            fails.append(f"{where}: repos must list some of {', '.join(REPOS)}")
            continue
        globs = as_list(fm.get("globs"))
        if fm.get("alwaysApply") is True:
            if set(repos) != set(REPOS):
                fails.append(f"{where}: always applied, so it attaches in every repository, but repos lists {repos}")
        elif globs:
            rx = [glob_regex(g) for g in globs]
            hits = [f for f in files if any(r.match(f) for r in rx)]
            if repo in repos and not hits:
                fails.append(f"{where}: lists {repo}, but its globs {globs} match no tracked file here")
            if repo not in repos and hits:
                fails.append(f"{where}: does not list {repo}, but its globs match {hits[0]} here")
        body = text[text.find("\n---\n", 4) + 5:]
        for lm in re.finditer(r"\]\((?!https?://|#)([^)\s]+)\)", body):
            raw = lm.group(1)
            target = raw.split("#", 1)[0].split("?", 1)[0]
            stem = os.path.splitext(os.path.basename(target))[0]
            if "/" in target.lstrip("./") or target.startswith(".."):
                fails.append(f"{where}: relative link {raw!r} leaves {RULES}/ and dangles in a copy")
            elif target.endswith((".mdc", ".md")) and stem not in estate_names:
                fails.append(f"{where}: links {raw!r}, which is not an estate rule, so a copy dangles")
    if fails:
        print(f"FAIL: rule scope ({repo}):")
        for f in fails:
            print("  " + f)
        return 1
    n_estate = len(estate_names)
    print(f"OK: {len(parsed)} rules load ({n_estate} estate, {len(parsed) - n_estate} {repo}); every estate rule attaches where it says.")
    return 0


GOOD = "---\ndescription: d\nalwaysApply: true\nscope: estate\nrepos: [core, gui, prism]\n---\n# x\n"


def selftest(repo: str) -> int:
    def run(rules: dict[str, str], extra: tuple[str, ...] = ("rust/a.rs",)) -> int:
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            for i in range(MIN_RULES):
                rules.setdefault(f"0{i}-filler.mdc", GOOD)
            for rel, body in {**{f"{RULES}/{k}": v for k, v in rules.items()}, **{e: "x\n" for e in extra}}.items():
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(body)
            subprocess.run(["git", "-C", d, "add", "-A"], check=True)
            return subprocess.run([sys.executable, __file__, "--repo", repo, "--root", d],
                                  capture_output=True, text=True).returncode

    estate_glob = "---\ndescription: d\nglobs:\n  - rust/**\nscope: estate\nrepos: [{r}]\n---\n"
    other = [r for r in REPOS if r != repo][0]
    cases = {
        "frontmatter missing": {"30-x.mdc": "# no frontmatter\n"},
        "frontmatter does not parse": {"30-x.mdc": "---\ndescription: a: b: c\n---\n"},
        "no scope": {"30-x.mdc": "---\ndescription: d\nalwaysApply: true\n---\n"},
        "number outside series": {"130-x.mdc": GOOD},
        "another repository's series": {"930-x.mdc" if repo != "prism" else "230-x.mdc":
                                        f"---\ndescription: d\nalwaysApply: true\nscope: {'prism' if repo != 'prism' else 'gui'}\n---\n"},
        "always applied, repos partial": {"30-x.mdc": "---\ndescription: d\nalwaysApply: true\nscope: estate\nrepos: [core]\n---\n"},
        "glob matches nothing here": {"30-x.mdc": estate_glob.format(r=repo).replace("rust/**", "nowhere/**")},
        "glob matches here, repo not listed": {"30-x.mdc": estate_glob.format(r=other)},
        "relative link out of the rules": {"30-x.mdc": GOOD + "[d](../../docs/x.md)\n"},
        "link to a repository's own rule": {"30-x.mdc": GOOD + "[d](125-y.mdc)\n"},
        "fragment link to a repository's own rule": {"30-x.mdc": GOOD + "[d](125-y.mdc#section)\n"},
        "query link to a repository's own rule": {"30-x.mdc": GOOD + "[d](125-y.mdc?x=1)\n"},
    }
    ok = True
    if run({"30-x.mdc": estate_glob.format(r=repo) + "[e](00-filler.mdc#h)\n"}) != 0:
        print("SELFTEST FAIL: a clean tree was refused")
        ok = False
    else:
        print("selftest: clean tree passes")
    for name, rules in cases.items():
        if run(dict(rules)) == 0:
            print(f"SELFTEST FAIL: {name!r} passed")
            ok = False
        else:
            print(f"selftest: {name} -> fails")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True, choices=REPOS)
    ap.add_argument("--root", default=".")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    return selftest(a.repo) if a.selftest else check(a.root, a.repo)


if __name__ == "__main__":
    sys.exit(main())
