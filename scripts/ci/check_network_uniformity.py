#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
"""Rule 71 on the Rust consensus surface: the network selects data, never
control flow.

Once `network == Testnet` decides whether a check runs, "testnet passed"
stops meaning "this logic is correct" and means "the logic testnet happens
to run is correct". This gate flags every test of a `Network` variant in the
fenced consensus crates' non-test code, against an annotated allowlist
(Rick, 2026-11-05: the Rust form of the gate the C++ fence carried until it
was deleted with the C++ host).

# What counts as a test of a variant

In each fragment of comment- and string-stripped code (split at `;`, `{`
and `}`, whitespace collapsed), a fragment naming `Network::Mainnet`,
`Testnet`, `Stagenet` or `Regtest` (under any path) is a hit when it
compares one with `==` or `!=` (either side), names one in `matches!`, in
`if let` or `while let`, or as a `match` arm (`=>`). Passing a variant as a
value is data and is not a hit.

# What is test code

An item under a `cfg` that holds only in a test build: `test`, or a feature
`check_test_only_features.py` registers as test-only for that crate (its
`TEST_ONLY` table, read here so the two never drift). `any(...)` is test
code only when every alternative is; `all(...)` when any is; `not(...)`
never. A file declared as a module under such a `cfg` is test code, and so
is every module under it.

# The checks (a bijection, as the C++ gate's was)

1. Every allowlist entry is hit (rule 47: a deleted branch removes its
   entry in the same change).
2. Every live hit equals an entry, exactly: file and normalized text.
3. The total hits equal the entry count. A duplicated branch matches an
   existing entry, so 1 and 2 stay green; only the totals disagree.

Every fenced crate must exist and enumerate at least one source file: an
empty fence is a missing subject, never a pass. The allowlist shrinks,
never grows silently (rule 71 §4): an entry is the rule-71 §2 ratification
trail or migration debt with a named owner, recorded beside it.

`--selftest` runs the extractor and the three checks against synthetic
inputs, one red case each.
"""

import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The Rust consensus crates (Rick, 2026-11-05). There is no shekyl-staking
# crate: staking's consensus rules live in shekyl-chain-rules and
# shekyl-economics, which are fenced.
FENCE = (
    "shekyl-chain-rules",
    "shekyl-chain-ingest",
    "shekyl-chain-store",
    "shekyl-difficulty",
    "shekyl-economics",
    "shekyl-consensus",
    "shekyl-mempool",
    "shekyl-chain-sync",
)

# (file, exact normalized text, disposition).
ALLOWLIST = (
    (
        "rust/shekyl-chain-rules/src/rule_set.rs",
        "Network::Mainnet | Network::Testnet | Network::Stagenet | Network::Regtest => {",
        "Migration debt toward the network's row (rule 71 §4): RuleSchedule::for_network "
        "selects each network's rule schedule by match, every arm the identity today. "
        "NETWORK_IDENTITY.md's census (the shekyl-node rules_of row) rules the schedule a "
        "row field; owner: the network-identity round (NI), which moves it into the row.",
    ),
)

VARIANT = r"(?:\w+::)*Network::(?:Mainnet|Testnet|Stagenet|Regtest)\b"
HIT_FORMS = (
    re.compile(r"[!=]=\s*" + VARIANT),
    re.compile(VARIANT + r"\s*[!=]="),
    re.compile(r"\bmatches!\s*\(.*" + VARIANT),
    re.compile(r"\b(?:if|while)\s+let\s+" + VARIANT),
    re.compile(VARIANT + r"[^,;{}]*=>"),
)


def test_only_features():
    """{crate: {feature}} from check_test_only_features.py's TEST_ONLY."""
    path = ROOT / "scripts" / "ci" / "check_test_only_features.py"
    spec = importlib.util.spec_from_file_location("check_test_only_features", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = {}
    for (crate, feature) in module.TEST_ONLY:
        out.setdefault(crate, set()).add(feature)
    return out


def strip(src):
    """`src` with comments and the contents of string and char literals
    blanked to spaces, newlines kept: the same length, so an offset in the
    result is the same offset in `src`."""
    out = list(src)
    i, n = 0, len(src)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif src.startswith("/*", i):
            start, depth, i = i, 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            blank(start, i)
        elif (m := re.match(r'b?r(#*)"', src[i:])) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            body = i + len(m.group(0))
            end = src.find('"' + m.group(1), body)
            end = n if end < 0 else end
            blank(body, end)
            i = end + 1 + len(m.group(1))
        elif src[i] == '"' or (src.startswith('b"', i) and (i == 0 or not src[i - 1].isalnum())):
            body = i + (2 if src[i] == "b" else 1)
            j = body
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(body, min(j, n))
            i = j + 1
        elif (m := re.match(r"b?'(\\.|\\u\{[0-9a-fA-F]+\}|[^\\'])'", src[i:])):
            blank(i + 1, i + len(m.group(0)) - 1)
            i += len(m.group(0))
        else:
            i += 1
    return "".join(out)


def split_args(text):
    """Top-level comma-separated arguments of a cfg predicate list."""
    args, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def test_only(pred, features):
    """Whether cfg predicate `pred` holds only in a test build."""
    pred = pred.strip()
    if pred == "test":
        return True
    m = re.fullmatch(r'feature\s*=\s*"([^"]*)"', pred)
    if m:
        return m.group(1) in features
    m = re.fullmatch(r"(any|all|not)\s*\((.*)\)", pred, re.S)
    if not m:
        return False
    kind, args = m.group(1), split_args(m.group(2))
    if kind == "any":
        return bool(args) and all(test_only(a, features) for a in args)
    if kind == "all":
        return any(test_only(a, features) for a in args)
    return False


CFG = re.compile(r"#\[cfg\((.*?)\)\]", re.S)


def cfg_attributes(code, raw):
    """(start, end, predicate) of each `#[cfg(...)]` in stripped `code`,
    balanced parentheses; the predicate is read from `raw` at the same
    span, so a feature's name survives the stripping."""
    out = []
    for m in re.finditer(r"#\[cfg\(", code):
        depth, j = 1, m.end()
        while j < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[j], 0)
            j += 1
        if code[j : j + 1] == "]":
            out.append((m.start(), j + 1, raw[m.end() : j - 1]))
    return out


def item_end(code, start):
    """End of the item that begins at `start`: its `;` at depth 0, or its
    braced body."""
    depth = 0
    j = start
    while j < len(code):
        ch = code[j]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ";" and depth == 0:
            return j + 1
        elif ch == "{" and depth == 0:
            braces = 0
            while j < len(code):
                if code[j] == "{":
                    braces += 1
                elif code[j] == "}":
                    braces -= 1
                    if braces == 0:
                        return j + 1
                j += 1
            return len(code)
        j += 1
    return len(code)


def drop_test_items(code, raw, features):
    """`code` with the items under a test-only cfg blanked."""
    out = list(code)
    for start, end, pred in cfg_attributes(code, raw):
        if test_only(pred, features):
            for k in range(start, item_end(code, end)):
                if out[k] != "\n":
                    out[k] = " "
    return "".join(out)


def test_module_files(path, code, raw, features):
    """Files declared as modules under a test-only cfg in `path`."""
    files = []
    for start, end, pred in cfg_attributes(code, raw):
        if not test_only(pred, features):
            continue
        m = re.match(
            r'\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;',
            code[end:],
        )
        if not m:
            continue
        path_attr = re.search(r'#\[\s*path\s*=\s*"([^"]*)"\s*\]', raw[end : end + m.end()])
        here = path.parent if path.name in ("lib.rs", "mod.rs", "main.rs") else path.parent / path.stem
        if path_attr:
            candidates = [path.parent / path_attr.group(1)]
        else:
            candidates = [here / f"{m.group(1)}.rs", here / m.group(1) / "mod.rs"]
        files.extend(c.resolve() for c in candidates if c.exists())
    return files


def hits_in(code):
    flat = re.sub(r"\s+", " ", code)
    out = []
    for frag in re.split(r"(?<=[;{}])", flat):
        frag = frag.strip()
        if re.search(VARIANT, frag) and any(f.search(frag) for f in HIT_FORMS):
            out.append(frag)
    return out


def crate_hits(crate, features, fail):
    src = ROOT / "rust" / crate / "src"
    if not src.is_dir():
        fail(f"fenced crate {crate} has no src/ (rule 47: the subject is missing)")
        return []
    files = sorted(src.rglob("*.rs"))
    if not files:
        fail(f"fenced crate {crate} enumerates no source files (rule 47)")
        return []
    excluded = set()
    for f in files:
        raw = f.read_text(encoding="utf-8")
        excluded.update(test_module_files(f, strip(raw), raw, features))
    out = []
    for f in files:
        resolved = f.resolve()
        if resolved in excluded or any(
            str(resolved).startswith(str(e.with_suffix("")) + "/") for e in excluded
        ):
            continue
        raw = f.read_text(encoding="utf-8")
        code = drop_test_items(strip(raw), raw, features)
        rel = str(f.relative_to(ROOT))
        out.extend((rel, text) for text in hits_in(code))
    return out


def check(hits, allowlist):
    errors = []
    for af, atext, _ in allowlist:
        if (af, atext) not in hits:
            errors.append(f"allowlisted branch no longer exists (observed 0); remove its entry: {af} : {atext}")
    entries = {(af, atext) for af, atext, _ in allowlist}
    for hf, htext in hits:
        if (hf, htext) not in entries:
            errors.append(
                f"unlisted Network-variant branch on the consensus surface (rule 71): {hf} : {htext}\n"
                "      the network selects data, never control flow: make it a row lookup, or ratify\n"
                "      the divergence (named, loud, rule 71 §2) and add an annotated entry"
            )
    if len(hits) != len(allowlist):
        listing = "\n".join(f"      {hf} : {htext}" for hf, htext in hits)
        errors.append(
            f"hit count ({len(hits)}) != allowlist entry count ({len(allowlist)}): a branch was "
            f"duplicated, or removed without its entry moving. Live hits:\n{listing}"
        )
    return errors


def selftest():
    features = {"harness"}
    src = """
        // if net == Network::Mainnet { } is a comment
        fn a() { let s = "Network::Testnet =="; }
        fn b(n: Network) -> u8 { if n == Network::Mainnet { 1 } else { 0 } }
        fn c(n: Network) -> bool { matches!(n, Network::Regtest) }
        fn d(n: Network) { if let Network::Stagenet = n {} }
        fn e(n: Network) -> u8 { match n { Network::Mainnet => 1, _ => 2 } }
        fn f() -> Rules { Rules::new(Network::Regtest) }
        #[cfg(test)] mod tests { fn t(n: Network) -> bool { n != Network::Testnet } }
        #[cfg(feature = "harness")] fn h(n: Network) -> bool { n == Network::Regtest }
        #[cfg(any(test, feature = "spans"))] fn p(n: Network) -> bool { n != Network::Stagenet }
    """
    found = hits_in(drop_test_items(strip(src), src, features))
    joined = " | ".join(found)
    for form in ("n == Network::Mainnet", "matches!(n, Network::Regtest)", "if let Network::Stagenet",
                 "Network::Mainnet => 1", "n != Network::Stagenet"):
        assert form in joined, f"the extractor missed {form!r}: {found}"
    for absent in ("Network::Testnet ==", "n != Network::Testnet", "n == Network::Regtest", "Rules::new(Network::Regtest)"):
        assert absent not in joined, f"the extractor flagged {absent!r}: {found}"
    assert test_only("any(test, feature = \"harness\")", features)
    assert not test_only("any(test, feature = \"spans\")", features), "a production alternative is production"
    assert test_only("all(test, unix)", features)
    assert not test_only("not(test)", features)
    entry = ("f.rs", "x == Network::Mainnet {", "why")
    hit = ("f.rs", "x == Network::Mainnet {")
    assert check([hit], (entry,)) == [], "a listed hit is clean"
    assert check([], (entry,)), "an entry nobody hits is red"
    assert check([hit, ("g.rs", "y != Network::Testnet {")], (entry,)), "an unlisted hit is red"
    assert check([hit, hit], (entry,)), "a duplicated branch is red on the totals"
    print("check_network_uniformity selftest: ok")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return 0
    features = test_only_features()
    errors = []
    hits = []
    for crate in FENCE:
        hits.extend(crate_hits(crate, features.get(crate, set()), errors.append))
    errors.extend(check(hits, ALLOWLIST))
    if errors:
        print("FAIL: rule 71 on the Rust consensus surface:")
        for e in errors:
            print(f"  {e}")
        return 1
    print(
        f"PASS: {len(hits)} Network-variant branch(es) on the consensus surface, each allowlisted "
        f"({len(FENCE)} crates fenced)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
