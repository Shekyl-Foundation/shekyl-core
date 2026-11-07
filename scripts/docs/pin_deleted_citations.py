#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Pin documentation citations of files a deletion removed.
#
# A deletion leaves documents citing `path:line` of a file that is gone. The
# ruling for that case (the C++ removal, 2026-11): the citation is pinned to
# the last commit that still holds the file, by script, in the form
#
#     `path` at `<sha>` (lines A–B)        (a single line is `(line N)`)
#
# which the citation gate (check_doc_code_citations.py) reads as an inline era
# and the dead-citation ratchet (check_doc_claims.py) no longer counts,
# because the token carries no `:line` any more.
#
# WHAT A CITATION IS comes from the gates, not from this file. A token is a
# candidate when either gate's own regex matches it:
#   - check_doc_claims.CITE, the ratchet's rooted `path:line[-line]`, with or
#     without backticks;
#   - check_doc_code_citations.CITATION_RE, the backticked `path[:range]`
#     that resolves by PATH SUFFIX (`cryptonote_core/blockchain.cpp:123`).
# It is pinned only when the path resolves, at the base, to exactly one file
# the diff base..head deleted, resolves to nothing at head, and every cited
# line exists at the era it is pinned to (`git show <era>:<path>`). Anything
# else is left as written and printed with the reason, for a human.
#
# THE ERA is the citation gate's, not a constant. A citation under a section
# pin (`Reviewed at **`<sha>`**`) or after an inline `at `<sha>`` on its own
# line already declares the revision it was read at, and is pinned there; only
# a citation whose era is HEAD (an asserts-is claim about the tree before the
# deletion) is pinned at the base. Such a citation keeps the line numbers it
# was written with; the pin records what it claimed, it does not re-derive it.
#
# A section that declares its era in a form the citation gate does not parse
# ("Anchors pinned to `dev` `<sha>`", which check_pinned_anchors.py reads) is
# still a declaration. Its citations pin at the base when the cited lines are
# identical there and at the declared sha when they are not, and either case
# where the two differ is printed as a `note`, so a pin never moves a
# citation onto lines the document did not read.
#
# DOCUMENTS THE CITATION GATE READS (its DEFAULT_DOCS and DEFERRED_DOCS) take
# the pin BEFORE the path: `at `<sha>` `path` (lines A–B)`. That gate selects
# the era from the nearest inline pin to the LEFT of a citation, so the
# trailing form would leave the path resolving at HEAD there and fail. A
# citation already governed by a pin keeps that pin and only loses its `:line`.
#
# LINKS. A markdown link to a deleted path fails the link gate whatever its
# text says. In a live document it becomes the same pinned prose (the link is
# dropped; its text is kept when the text is not itself the citation). In a
# records-was document (check_doc_claims' RECORDS_WAS_DIRS / _FILES) the text
# is history and is not rewritten: the link joins docs/ci/link-allowlist.txt
# with its reason, as the dated records of earlier deletions did. A link on a
# fenced or commented line is allowlisted for the same reason: it is an
# example, not a claim.
#
# docs/FOLLOWUPS.md is treated the same way: its rows are keyed by their exact
# heading text, so its text is not rewritten and its links are allowlisted.
#
# Records-was documents' citations (as opposed to links) are left alone: the
# ratchet does not count them, and their era is when they were written, which
# a pin at the base would misstate.
#
# Idempotent: a pinned citation has no `:line` and a pinned link is no link,
# so a second run finds nothing; an allowlist entry already present is not
# added twice.
#
# Usage: pin_deleted_citations.py --base <sha> [--head <rev>] [--dry-run]
#        pin_deleted_citations.py --selftest
# Exit 0 = ran (and, with --dry-run, nothing would change); 1 = --dry-run found
# changes to make; 2 = could not run. Citations left for a human are printed
# as `left` lines either way.

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts", "ci"))

import check_doc_claims as claims  # noqa: E402  (the ratchet's CITE)
import check_doc_code_citations as citations  # noqa: E402  (era + suffix rules)
import check_doc_links as links  # noqa: E402  (what a link target is)

ALLOWLIST = os.path.join("docs", "ci", "link-allowlist.txt")

# Files this script never edits. CLAUDE.md is orientation maintained by hand
# and is read by no documentation gate.
NEVER_EDIT = ("CLAUDE.md",)

# Files whose text is not rewritten, so their links to deleted paths are
# allowlisted instead: FOLLOWUPS rows are keyed by their exact heading text
# (scripts/ci/followups_owner_grandfather.txt), and a pin inside a heading
# un-grandfathers the row.
TEXT_FROZEN = ("docs/FOLLOWUPS.md",)

SPAN_RE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")
FOLLOW_RE = re.compile(
    r"(\s*(?:,\s*and|,|/|–|—|-|\bto\b|\band\b)\s*)(`?)(:?)(\d+)(?:[–—-](\d+))?\2"
)
RANGE_SEPS = ("–", "—", "-", "to")
LINK_FULL_RE = re.compile(r"\]\(([^)#\s]+)(#[^)\s]*)?\)")
FRAG_RE = re.compile(r"^#L(\d+)(?:-L?(\d+))?$")
TEXT_CITE_RE = re.compile(r"^([A-Za-z0-9_./{},-]*?)(?::(\d+(?:[–—-]\d+)?(?:,\s*\d+(?:[–—-]\d+)?)*))?$")


def git(root, *args):
    proc = subprocess.run(["git", "-C", root, *args], capture_output=True,
                          text=True, errors="replace", check=False)
    return proc.returncode, proc.stdout


class Tree:
    """Blobs, gitlinks and directories of one revision, with line counts."""

    def __init__(self, root, rev):
        self.root, self.rev = root, rev
        rc, out = git(root, "ls-tree", "-r", "-z", rev)
        self.ok = rc == 0
        self.blobs, self.gitlinks, self.dirs = set(), set(), set()
        for entry in out.split("\0") if self.ok else ():
            if not entry:
                continue
            meta, path = entry.split("\t", 1)
            kind = meta.split()[1]
            (self.blobs if kind == "blob" else self.gitlinks).add(path)
        for path in self.blobs | self.gitlinks:
            parts = path.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                self.dirs.add("/".join(parts[:i]))
        self._lines = {}

    def resolve(self, token):
        """The ratchet's resolution (exact, then crate-relative under rust/),
        then the citation gate's path suffix."""
        if token in self.blobs:
            return [token]
        if not token.startswith(claims.ROOTS) and "rust/" + token in self.blobs:
            return ["rust/" + token]
        return citations.resolve_path(token, self.blobs)

    def content(self, path):
        if path not in self._lines:
            rc, out = git(self.root, "show", f"{self.rev}:{path}")
            if rc != 0:
                self._lines[path] = None
            else:
                body = out.split("\n")
                if body and body[-1] == "":
                    body.pop()
                self._lines[path] = body
        return self._lines[path]

    def lines(self, path):
        body = self.content(path)
        return -1 if body is None else len(body)

    def cited(self, token, items):
        """The cited lines of `token`, or None when they do not resolve."""
        found = self.resolve(token)
        body = self.content(found[0]) if len(found) == 1 else None
        if body is None:
            return None
        return [body[a - 1:b] for a, b in items]


class Run:
    def __init__(self, root, base, head, pin_first_docs):
        self.root = root
        rc, full = git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
        if rc != 0:
            raise SystemExit(f"pin_deleted_citations: base `{base}` is not a commit here")
        self.base = full.strip()[:10]
        self.head = head
        self.trees = {}
        self.base_tree = self.tree(self.base)
        self.head_tree = self.tree(head)
        rc, out = git(root, "diff", "--name-only", "-M", "--diff-filter=D",
                      self.base, head)
        if rc != 0:
            raise SystemExit("pin_deleted_citations: git diff failed")
        self.deleted = {p for p in out.split("\n") if p}
        self.deleted_gitlinks = {p for p in self.deleted if p in self.base_tree.gitlinks}
        self.deleted_dirs = self.base_tree.dirs - self.head_tree.dirs
        self.pin_first_docs = set(pin_first_docs)
        self.pinned = self.links_pinned = 0
        self.allowlisted = []
        self.left = []
        self.notes = []
        self.touched = set()
        self.cut_starts = set()

    def tree(self, rev):
        if rev not in self.trees:
            self.trees[rev] = Tree(self.root, rev)
        return self.trees[rev]

    # ---- classification -------------------------------------------------

    def under_deleted_gitlink(self, path):
        return any(path == g or path.startswith(g + "/") for g in self.deleted_gitlinks)

    def deleted_target(self, repo_path):
        p = repo_path.rstrip("/")
        if p in self.head_tree.blobs or p in self.head_tree.dirs:
            return False
        return (p in self.deleted or p in self.deleted_dirs
                or self.under_deleted_gitlink(p))

    def records_was(self, rel):
        parts = rel.split("/")
        if parts[0] != "docs":
            return False
        return (any(d in parts[:-1] for d in claims.RECORDS_WAS_DIRS)
                or parts[-1] in claims.RECORDS_WAS_FILES)

    # ---- rendering ------------------------------------------------------

    @staticmethod
    def render_lines(items):
        parts = [str(a) if a == b else f"{a}–{b}" for a, b in items]
        if len(parts) == 1:
            return ("line " if items[0][0] == items[0][1] else "lines ") + parts[0]
        return "lines " + ", ".join(parts[:-1]) + " and " + parts[-1]

    def render(self, rel, token, era, governed, items):
        tail = f" ({self.render_lines(items)})" if items else ""
        if rel in self.pin_first_docs:
            if governed:
                return f"`{token}`{tail}"
            return f"at `{era}` `{token}`{tail}"
        return f"`{token}` at `{era}`{tail}"

    def verify(self, era, token, items):
        """None when every cited line of `token` exists at `era`, else why."""
        tree = self.tree(era)
        if not tree.ok:
            return f"era `{era}` is not reachable here"
        found = tree.resolve(token.rstrip("/"))
        if not found and token.rstrip("/") in tree.dirs:
            return None if not items else "a directory has no lines"
        if len(found) != 1:
            return f"`{token}` resolves to {len(found)} files at `{era}`"
        n = tree.lines(found[0])
        for a, b in items:
            if a < 1 or b < a or b > n:
                return f"line {b} is past the {n} lines of {found[0]} at `{era}`"
        return None

    def era_of(self, line, pos, section_era):
        era = citations.era_for_citation(line, pos, section_era)
        if era == citations.HEAD:
            return self.base, False
        return era, True

    def settle(self, era, declared, token, items):
        """(era, note) for a citation under an UNPARSED declaration.

        The ruling pins at the base. That is exact when the cited lines are
        the same at the document's declared sha; when they moved, the
        declared sha is the one that still says what the document read, and
        the choice is reported. A declared sha that does not hold the lines
        (a range of shas, a later re-read) falls back to the base, reported.
        """
        if not declared or not items:
            return era, None
        at_declared = self.tree(era).cited(token, items) if self.tree(era).ok else None
        at_base = self.base_tree.cited(token, items)
        if at_declared is not None and at_declared == at_base:
            return self.base, None
        if at_declared is not None and self.verify(era, token, items) is None:
            return era, (f"pinned at the declared `{era}`: the cited lines differ "
                         f"at the base")
        return self.base, f"the declared `{era}` does not hold these lines; pinned at the base"

    # ---- the per-line passes --------------------------------------------

    def follow_ons(self, line, end, items):
        """Absorb `:N` follow-ons after a citation: `–`:M`` extends the last
        range, `, `:M`` adds one. Returns the new end."""
        while True:
            m = FOLLOW_RE.match(line, end)
            if not m:
                return end
            sep = m.group(1).strip()
            ranged = sep in RANGE_SEPS
            if not m.group(3) and not (ranged and m.group(2)):
                return end  # a bare number is a follow-on only as `–`N``
            a = int(m.group(4))
            b = int(m.group(5) or a)
            if ranged and not m.group(5):
                items[-1] = (items[-1][0], a)
            else:
                items.append((a, b))
            end = m.end()

    def citation_edits(self, rel, line, lineno, section_era, declared=False,
                       contested=()):
        # (span start, span end, inner start, inner end) of each code span
        spans = [(m.start(), m.end(), m.start(2), m.end(2)) for m in SPAN_RE.finditer(line)]
        found = {}
        for m in claims.CITE.finditer(line):
            found.setdefault(m.start(1), (m.start(1), m.end(), m.group(1),
                                          int(m.group(2)), m.group(3), True))
        for m in citations.CITATION_RE.finditer(line):
            start = m.start(1)
            if start in found:
                continue
            found[start] = (start, m.end() - 1, m.group(1),
                            int(m.group(2)) if m.group(2) else None, m.group(3),
                            False)
        edits = []
        for start, end, token, first, last, counted in sorted(found.values()):
            if start in self.cut_starts:
                continue
            if first is None and rel not in self.pin_first_docs:
                continue  # a path named without lines is a mention, not a cite
            base_hits = self.base_tree.resolve(token)
            if self.under_deleted_gitlink(token):
                self.left.append((rel, lineno, token, "inside a deleted submodule; "
                                  "its lines cannot be read at the base"))
                continue
            if not any(h in self.deleted for h in base_hits):
                continue
            head_hits = self.head_tree.resolve(token)
            if head_hits:
                # Still names a file at head. When it was ambiguous at the base
                # too, the deletion changed nothing a reader resolves; when it
                # was unique, it now names a DIFFERENT file, which is a human's.
                if len(base_hits) == 1:
                    self.left.append((rel, lineno, token, "still resolves at head "
                                      "to " + ", ".join(head_hits)))
                continue
            if len(base_hits) != 1:
                self.left.append((rel, lineno, token, f"resolves to {len(base_hits)} "
                                  "files at the base and none at head"))
                continue
            span = next((sp for sp in spans if sp[2] <= start < sp[3]), None)
            if span:
                if (span[2], span[3]) != (start, end):
                    self.left.append((rel, lineno, line[span[2]:span[3]],
                                      "the code span holds more than the citation"))
                    continue
                cut_a, cut_b = span[0], span[1]
            else:
                cut_a, cut_b = start, end
            era, governed = self.era_of(line, start, section_era)
            if (governed or contested) and not counted:
                # Already read at a declared era by the citation gate, and the
                # ratchet does not count it: it is pinned as it stands.
                continue
            if contested:
                self.left.append((rel, lineno, token, "era declarations "
                                  + ", ".join(contested) + " all claim this line"))
                continue
            if first is None:
                if governed:
                    continue  # the gate already reads it at a declared era
                if line[cut_b:].startswith(" at `"):
                    continue
                why = self.verify(era, token, [])
                if why:
                    self.left.append((rel, lineno, token, why))
                    continue
                edits.append((cut_a, cut_b, f"at `{era}` `{token}`"))
                continue
            items = [(first, int(last) if last else first)]
            new_end = self.follow_ons(line, cut_b, items)
            if declared and era == section_era:
                # The citation gate does not parse this era, so a pin-first
                # document must still carry it inline.
                governed = False
                era, note = self.settle(era, True, token, items)
                if note:
                    self.notes.append((rel, lineno, line[cut_a:new_end], note))
            why = self.verify(era, token, items)
            if why:
                self.left.append((rel, lineno, line[cut_a:new_end], why))
                continue
            edits.append((cut_a, new_end, self.render(rel, token, era, governed, items)))
        return edits

    def link_edits(self, rel, doc_dir, line, lineno, section_era, allowlist_only,
                   declared=False):
        edits = []
        for m in LINK_FULL_RE.finditer(line):
            target, frag = m.group(1), m.group(2) or ""
            if not links.path_shaped(target):
                continue
            repo = os.path.normpath(os.path.join(doc_dir, target))
            if repo.startswith(".."):
                continue
            repo = repo.replace(os.sep, "/") + ("/" if target.endswith("/") else "")
            if not self.deleted_target(repo):
                continue
            # the matching `[`
            depth, i = 0, m.start()
            while i >= 0:
                ch = line[i]
                if ch == "]":
                    depth += 1
                elif ch == "[":
                    depth -= 1
                    if depth == 0:
                        break
                i -= 1
            if i < 0:
                self.left.append((rel, lineno, m.group(0), "no opening bracket on this line"))
                continue
            text = line[i + 1:m.start()]
            if allowlist_only:
                if rel.startswith("docs/"):
                    self.allowlisted.append((rel, target))
                else:
                    self.left.append((rel, lineno, line[i:m.end()], "an example or "
                                      "record outside docs/, which no allowlist reads"))
                continue
            items = []
            fm = FRAG_RE.match(frag)
            if fm:
                a = int(fm.group(1))
                items = [(a, int(fm.group(2) or a))]
            era, governed = self.era_of(line, i, section_era)
            new = self.link_text(rel, text, repo, era, governed, items)
            if new is None:
                self.left.append((rel, lineno, line[i:m.end()], "link text not understood"))
                continue
            replacement, token, cited = new
            if declared and era == section_era:
                governed = False
            if declared and era == section_era and cited:
                settled, note = self.settle(era, True, token, cited)
                if settled != era:
                    new = self.link_text(rel, text, repo, settled, governed, items)
                    replacement, token, cited = new
                    era = settled
                if note:
                    self.notes.append((rel, lineno, line[i:m.end()], note))
            why = self.verify(era, token, cited)
            if why:
                self.left.append((rel, lineno, line[i:m.end()], why))
                continue
            edits.append((i, m.end(), replacement))
        return edits

    def link_text(self, rel, text, repo, era, governed, frag_items):
        """(replacement, token verified, lines verified) for one link."""
        span = SPAN_RE.fullmatch(text)
        # Plain link text shaped like a path (`[cryptonote_config.h:144](...)`)
        # is the same citation without its backticks.
        plain_path = not span and re.search(r"[/:.]", text) and TEXT_CITE_RE.match(text)
        if span or plain_path:
            inner = span.group(2) if span else text
            tm = TEXT_CITE_RE.match(inner)
            if tm:
                path, ranges = tm.group(1), tm.group(2)
                items = frag_items
                if ranges:
                    items = []
                    for part in re.split(r",\s*", ranges):
                        ends = re.split(r"[–—-]", part)
                        items.append((int(ends[0]), int(ends[-1])))
                alternatives = self.expand(path)
                if not path:
                    token = self.shortest_suffix(repo)
                    return self.render(rel, token, era, governed, items), token, items
                if any(repo.rstrip("/") == alt.rstrip("/")
                       or repo.rstrip("/").endswith("/" + alt.rstrip("/"))
                       for alt in alternatives):
                    # A file is verified as WRITTEN, so the citation gate's
                    # suffix rule can resolve it; a directory or a brace
                    # pattern (`a.{c,h}`) is verified by the path it links.
                    plain = path == alternatives[0] and not repo.endswith("/")
                    return (self.render(rel, path, era, governed, items),
                            path if plain else repo, items)
        token = repo
        return (f"{text} ({self.render(rel, token, era, governed, frag_items)})",
                token, frag_items)

    @staticmethod
    def expand(path):
        m = re.search(r"\{([^{}]*)\}", path)
        if not m:
            return [path]
        return [path[:m.start()] + alt + path[m.end():] for alt in m.group(1).split(",")]

    def shortest_suffix(self, repo):
        parts = repo.rstrip("/").split("/")
        for k in range(1, len(parts) + 1):
            cand = "/".join(parts[-k:])
            if len(self.base_tree.resolve(cand)) == 1:
                return cand
        return repo

    # ---- files ----------------------------------------------------------

    def documents(self):
        rc, out = git(self.root, "ls-files", "-z", "--", "*.md")
        if rc != 0:
            raise SystemExit("pin_deleted_citations: git ls-files failed")
        for rel in sorted(p for p in out.split("\0") if p):
            if rel in NEVER_EDIT or not os.path.isfile(os.path.join(self.root, rel)):
                continue
            yield rel

    def process(self, rel):
        path = os.path.join(self.root, rel)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        lines = text.split("\n")
        visible = claims.strip_fences(text).split("\n")
        section_eras = citations.eras_for_lines(lines, inline=False)
        # Lines under an era declaration the citation gate does not parse
        # ("verified at `dev` `<sha>`"): the document still states the era
        # they were read at, which `settle` weighs against the base. A line
        # two such declarations claim is left for a human.
        declared = {}
        for section in citations.unparsed_era_sections(
                lines, citations.eras_for_lines(lines)):
            for n in section["lines"]:
                declared.setdefault(n, set()).add(section["declaration"].strip("`"))
        records = self.records_was(rel) or rel in TEXT_FROZEN
        if len(visible) not in (len(lines), len(lines) - 1):
            raise SystemExit(f"pin_deleted_citations: {rel} splits into lines "
                             "differently for the fence scanner; not editing it")
        doc_dir = os.path.dirname(rel)
        changed = False
        for idx, line in enumerate(lines):
            lineno = idx + 1
            seen = visible[idx] if idx < len(visible) else ""
            example = seen != line
            section = section_eras.get(lineno, citations.HEAD)
            one = len(declared.get(lineno, ())) == 1
            if one:
                section = next(iter(declared[lineno]))
            edits = self.link_edits(rel, doc_dir, line, lineno, section,
                                    allowlist_only=records or example, declared=one)
            if records or example:
                continue
            # a citation inside a pinned link's text went with the link
            self.cut_starts = {p for a, b, _ in edits for p in range(a, b)}
            if len(declared.get(lineno, ())) > 1:
                # Treated as governed (pinned as it stands) unless the ratchet
                # counts it; a counted one cannot pick between the eras.
                self.citation_edits(rel, line, lineno, section,
                                    contested=sorted(declared[lineno]))
            else:
                edits += self.citation_edits(rel, line, lineno, section, declared=one)
            if not edits:
                continue
            edits.sort()
            for (a1, b1, _), (a2, _, _) in zip(edits, edits[1:]):
                if a2 < b1:
                    raise SystemExit(f"pin_deleted_citations: overlapping edits "
                                     f"at {rel}:{lineno}")
            for a, b, new in reversed(edits):
                old = line[a:b]
                print(f"pin   {rel}:{lineno}: {old}  ->  {new}")
                if "](" in old:
                    self.links_pinned += 1
                else:
                    self.pinned += 1
                line = line[:a] + new + line[b:]
            lines[idx] = line
            changed = True
        if changed:
            self.touched.add(rel)
        return "\n".join(lines) if changed else None

    def allowlist_additions(self):
        path = os.path.join(self.root, ALLOWLIST)
        existing = set()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    entry = raw.split("#", 1)[0].strip()
                    if ":" in entry:
                        existing.add(tuple(entry.split(":", 1)))
        new = sorted({e for e in self.allowlisted
                      if e not in existing and e[0].startswith("docs/")})
        return path, new

    def write_allowlist(self, path, new):
        header = (f"# Deleted after `{self.base}`, which still holds them: links "
                  f"in records-was documents and FOLLOWUPS rows keep the path as "
                  f"written (rule 91).")
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        if header not in body:
            body = body.rstrip("\n") + "\n\n" + header + "\n"
        for rel, target in new:
            kind = ("rows are keyed by their heading text" if rel in TEXT_FROZEN
                    else "records-was")
            body += (f"{rel}:{target} # {kind}; the target was deleted after "
                     f"`{self.base}`, the commit that still holds it (rule 91)\n")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)


def run(root, base, head, pin_first_docs, write):
    job = Run(root, base, head, pin_first_docs)
    rewrites = {}
    for rel in job.documents():
        out = job.process(rel)
        if out is not None:
            rewrites[rel] = out
    allow_path, allow_new = job.allowlist_additions()
    for rel, target in allow_new:
        print(f"allow {rel}: {target}")
    for rel, lineno, token, why in job.notes:
        print(f"note  {rel}:{lineno}: {token} -- {why}")
    for rel, lineno, token, why in job.left:
        print(f"left  {rel}:{lineno}: {token} -- {why}")
    if write:
        for rel, text in rewrites.items():
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        if allow_new:
            job.write_allowlist(allow_path, allow_new)
            job.touched.add(ALLOWLIST)
    print(f"pin_deleted_citations: {len(job.deleted)} paths deleted after "
          f"`{job.base}`; {job.pinned} citation(s) and {job.links_pinned} link(s) "
          f"pinned, {len(allow_new)} link(s) allowlisted, {len(job.left)} left for "
          f"a human; {len(job.touched) if write else len(rewrites)} file(s) "
          f"{'touched' if write else 'would change'}")
    return job, bool(rewrites or allow_new)


# ---- selftest -----------------------------------------------------------

def selftest():
    tmp = tempfile.mkdtemp(prefix="pin-deleted-")
    try:
        def sh(*args):
            proc = subprocess.run(["git", "-C", tmp, *args], capture_output=True,
                                  text=True, check=False)
            if proc.returncode != 0:
                raise SystemExit(f"selftest setup: git {' '.join(args)}: {proc.stderr}")
            return proc.stdout.strip()

        def put(rel, body):
            os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
            with open(os.path.join(tmp, rel), "w", encoding="utf-8") as fh:
                fh.write(body)

        sh("init", "-q")
        sh("config", "user.email", "selftest@example.invalid")
        sh("config", "user.name", "selftest")
        sh("config", "commit.gpgsign", "false")
        put("src/core/a.cpp", "".join(f"l{i}\n" for i in range(1, 11)))
        put("src/core/b.h", "x\n")
        put("rust/k/src/lib.rs", "".join(f"r{i}\n" for i in range(1, 6)))
        put("docs/ci/link-allowlist.txt", "# allowlist\n")
        doc = "\n".join([
            "# Doc",
            "rooted `src/core/a.cpp:3` here",
            "suffix `core/a.cpp:2–4` here",
            "follow `src/core/a.cpp:3`–`:5`, and `src/core/a.cpp:6`, `:8`",
            "past `src/core/a.cpp:99` stays",
            "live `rust/k/src/lib.rs:2` stays",
            "link [`src/core/a.cpp:7`](../src/core/a.cpp) end",
            "prose [the gate](../src/core/a.cpp#L9) end",
            "follow-on [`:4`](../src/core/a.cpp#L4) end",
            "plain [core/a.cpp:5](../src/core/a.cpp#L5) end",
            "pinned `src/core/b.h:1` at `deadbeef` is not a pin to its right",
            "```",
            "fenced `src/core/a.cpp:3` example",
            "```",
            "## Old",
            "Reviewed at **`BASE`**",
            "section `src/core/a.cpp:10` row",
            "section suffix `core/a.cpp:9` stays",
            "",
        ])
        put("docs/d.md", doc)
        put("docs/completed/r.md", "rec [`src/core/a.cpp:3`](../../src/core/a.cpp) `src/core/a.cpp:3`\n")
        put("docs/gate.md", "g `src/core/a.cpp` and `src/core/a.cpp:2` and `rust/k/src/lib.rs`\n")
        sh("add", "-A")
        sh("commit", "-q", "-m", "base")
        base = sh("rev-parse", "HEAD")[:10]
        with open(os.path.join(tmp, "docs/d.md"), encoding="utf-8") as fh:
            body = fh.read().replace("BASE", base)
        put("docs/d.md", body)
        os.remove(os.path.join(tmp, "src/core/a.cpp"))
        os.remove(os.path.join(tmp, "src/core/b.h"))
        sh("add", "-A")
        sh("commit", "-q", "-m", "delete")

        failures = []

        def expect(rel, *needles, absent=()):
            with open(os.path.join(tmp, rel), encoding="utf-8") as fh:
                got = fh.read()
            for n in needles:
                if n not in got:
                    failures.append(f"{rel}: missing {n!r}")
            for n in absent:
                if n in got:
                    failures.append(f"{rel}: still has {n!r}")

        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            job, _ = run(tmp, base, "HEAD", {"docs/gate.md"}, write=True)
        b = base
        expect("docs/d.md",
               f"rooted `src/core/a.cpp` at `{b}` (line 3) here",
               f"suffix `core/a.cpp` at `{b}` (lines 2–4) here",
               f"follow `src/core/a.cpp` at `{b}` (lines 3–5), and "
               f"`src/core/a.cpp` at `{b}` (lines 6 and 8)",
               "past `src/core/a.cpp:99` stays",
               "live `rust/k/src/lib.rs:2` stays",
               f"link `src/core/a.cpp` at `{b}` (line 7) end",
               f"prose the gate (`src/core/a.cpp` at `{b}` (line 9)) end",
               f"follow-on `a.cpp` at `{b}` (line 4) end",
               f"plain `core/a.cpp` at `{b}` (line 5) end",
               f"pinned `src/core/b.h` at `{b}` (line 1) at `deadbeef`",
               "fenced `src/core/a.cpp:3` example",
               f"section `src/core/a.cpp` at `{b}` (line 10) row",
               "section suffix `core/a.cpp:9` stays")
        expect("docs/completed/r.md", "rec [`src/core/a.cpp:3`](../../src/core/a.cpp) `src/core/a.cpp:3`")
        expect("docs/ci/link-allowlist.txt", "docs/completed/r.md:../../src/core/a.cpp # records-was")
        expect("docs/gate.md",
               f"g at `{b}` `src/core/a.cpp` and at `{b}` `src/core/a.cpp` (line 2) "
               "and `rust/k/src/lib.rs`")
        if not any("src/core/a.cpp:99" in str(x) for x in job.left):
            failures.append("a line past end of file was not reported")
        # idempotent: nothing left to do
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _, more = run(tmp, base, "HEAD", {"docs/gate.md"}, write=False)
        if more:
            failures.append("a second run would change files:\n" + buf.getvalue())
        if failures:
            print("SELFTEST FAIL:\n  " + "\n  ".join(failures))
            return 1
        print("pin_deleted_citations selftest: ok")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        usage="pin_deleted_citations.py --base <sha> [--head <rev>] [--dry-run] | --selftest")
    ap.add_argument("--base", help="the last commit that holds the deleted files")
    ap.add_argument("--head", default="HEAD", help="the tree after the deletion")
    ap.add_argument("--dry-run", action="store_true", help="report, write nothing")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.base:
        ap.error("--base is required")
    pin_first = set(citations.DEFAULT_DOCS) | set(citations.DEFERRED_DOCS)
    _, changes = run(ROOT, args.base, args.head, pin_first, write=not args.dry_run)
    return 1 if (args.dry_run and changes) else 0


if __name__ == "__main__":
    sys.exit(main())
