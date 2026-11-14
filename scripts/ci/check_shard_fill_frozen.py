#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The shard-fill chain is frozen, and it takes no new consumers.

# What is held

`CHAIN_FORGE.md` `CF-R17` (Rick, 2026-11-13): the checked-in shard-fill
chain (`rust/shekyl-harness-spender/vectors/shard-fill.bin`) stays exactly
as it is until `CF-5` replaces it with a forged chain and deletes it. Its
bytes do not regenerate (proving draws fresh randomness), so every
re-capture would add another 11.5 MB to the repository's history for
good. And nothing new may come to depend on it: a new test that wants a
chain at that scale waits for the forge.

  1. **Frozen.** The file exists and its SHA-256 is `PINNED_SHA256`.
  2. **No new consumer.** Outside comments, only the files in `READERS`
     name one of the chain's access points (`ACCESS`): the type's loader,
     its path, its reserved-coinbase count, and the ingest's and the
     store's prefix helpers built on it.
  3. **The list only shrinks.** Every file in `READERS` exists and still
     names an access point. A consumer that moved to the forge's chains
     is taken off the list in the change that moves it, so `READERS` is
     also `CF-5`'s migration list (`CHAIN_FORGE.md` §12.1, `CF-5`).

# A consensus change that would invalidate the chain

`CF-R20`: the normal path is that `CF-5`'s replacement lands first. If such
a change has to land before it, Rick approves one re-capture explicitly,
and the pin update changes `PINNED_SHA256` and `PIN_REASON` together,
citing that approval. The tests are never turned off; this gate blocking
the consensus PR is how the case is decided.

Comments are not consumers: a line whose code starts with `//` is skipped,
so prose may name the helpers.

# Rule 47

The gate asserts its subject before it judges: the file is present and
hashed, and the scan reads Rust sources and finds the owner's own access
points (a scan over zero files, or one that finds nothing, is not a gate).
`--selftest` plants each failure in a scratch tree and proves each limb
reports it, then proves a clean tree passes.
"""

from __future__ import annotations

import hashlib
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

CHAIN = "rust/shekyl-harness-spender/vectors/shard-fill.bin"
PINNED_SHA256 = "ed40b30181d3295ace07824ea23d7bae8a4967a69cc72ff6ad9269b94d79514b"
# Why the pin is this hash. A re-capture under `CF-R20`'s exception
# replaces both, and cites Rick's approval here.
PIN_REASON = (
    "24ec78897: the first capture (Rick's shard-fill ruling, option A, 2026-11-11); "
    "frozen at it by CF-R17"
)

# What reaches the chain's bytes. Whole tokens, matched outside comments.
ACCESS = (
    r"CapturedChain::shard_fill\b",
    r"\bshard_fill_path\b",
    r"\bSHARD_FILL_RESERVED_COINBASES\b",
    r"shard-fill\.bin",
    r"\bload_shard_fill\b",
    r"\bclose_shards\b",
    r"\bstore_with_prefix\b",
    r"\bBuilder::captured\b",
    r"\bshard_fill::",
)
ACCESS_RE = re.compile("|".join(ACCESS))

# The chain's owner, its two readers, and their consumers at the freeze
# (`bfdc84a30` plus #1370). Removing an entry is how a consumer leaves;
# adding one needs a ruling that reopens `CF-R17`.
READERS = (
    # The owner: the format, the loader and the path.
    "rust/shekyl-harness-spender/src/captured.rs",
    # The ingest's reader (`load_shard_fill`, `close_shards`) and its users.
    "rust/shekyl-chain-ingest/src/scenario_shard.rs",
    "rust/shekyl-chain-ingest/src/archival_pop_roundtrip_tests.rs",
    "rust/shekyl-chain-ingest/src/archival_slash_tests.rs",
    "rust/shekyl-chain-ingest/src/bundle_producer_gate_tests.rs",
    "rust/shekyl-chain-ingest/src/pool_submit_tests.rs",
    "rust/shekyl-chain-ingest/src/rpc_store_facts_tests/below_horizon.rs",
    "rust/shekyl-chain-ingest/src/scenario_emission_tests.rs",
    "rust/shekyl-chain-ingest/src/scenario_join_tests.rs",
    # The store's reader (`store_with_prefix`, the capture writer) and its
    # users.
    "rust/shekyl-chain-store/src/store/shard_fill.rs",
    "rust/shekyl-chain-store/src/store/prune_tests.rs",
    "rust/shekyl-chain-store/src/store/slash_scan_bench_tests.rs",
)
OWNER = "rust/shekyl-harness-spender/src/captured.rs"


def code_hits(text: str) -> list[int]:
    """Line numbers (1-based) whose code names an access point."""
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("//"):
            continue
        if ACCESS_RE.search(line):
            hits.append(number)
    return hits


def rust_sources(root: Path) -> list[Path]:
    return sorted(p for p in (root / "rust").rglob("*.rs") if "/target/" not in p.as_posix())


def check(root: Path, pinned: str, readers: tuple[str, ...]) -> list[str]:
    errors: list[str] = []
    if not PIN_REASON.strip():
        errors.append("PIN_REASON is empty: a pin names why it is this hash (CF-R20)")

    chain = root / CHAIN
    if not chain.is_file():
        return [f"{CHAIN} is missing: the freeze has no subject (CF-R17 ends only in CF-5)"]
    digest = hashlib.sha256(chain.read_bytes()).hexdigest()
    if digest != pinned:
        errors.append(
            f"{CHAIN} changed (sha256 {digest}, pinned {pinned}). The chain is frozen until "
            "CF-5 (CHAIN_FORGE.md CF-R17): its bytes do not regenerate, so a re-capture adds "
            "11.5 MB to history for good. Restore the file. If a consensus change must land "
            "before CF-5's replacement, Rick approves one re-capture explicitly, and the pin "
            "update changes PINNED_SHA256 and PIN_REASON together, citing it (CF-R20). The "
            "tests are never turned off."
        )

    sources = rust_sources(root)
    if not sources:
        return errors + ["no Rust source under rust/: the scan has no subject"]

    allowed = set(readers)
    seen: set[str] = set()
    for path in sources:
        rel = path.relative_to(root).as_posix()
        hits = code_hits(path.read_text(encoding="utf-8", errors="replace"))
        if not hits:
            continue
        seen.add(rel)
        if rel not in allowed:
            lines = ", ".join(str(n) for n in hits[:5])
            errors.append(
                f"{rel}:{lines}: a new consumer of the frozen shard-fill chain. Nothing new "
                "depends on it (CHAIN_FORGE.md CF-R17); a chain at that scale waits for the forge."
            )

    if OWNER not in seen:
        errors.append(f"{OWNER} names none of the access points: the scan matches nothing")

    for rel in readers:
        if not (root / rel).is_file():
            errors.append(f"{rel} is listed in READERS and does not exist: take it off the list")
        elif rel not in seen:
            errors.append(
                f"{rel} is listed in READERS and no longer reads the chain: take it off the list "
                "(CF-5's migration list shrinks as consumers move)"
            )
    return errors


def selftest() -> int:
    good = b"frozen chain bytes"
    pinned = hashlib.sha256(good).hexdigest()
    owner = "pub fn shard_fill_path() -> PathBuf { todo!() }\n"
    user = "fn t() { let x = close_shards(&mut s, &mut m, 1, 1); }\n"
    readers = (OWNER, "rust/a/src/user.rs")

    def tree(tmp: Path, *, chain: bytes | None = good, extra: dict[str, str] | None = None,
             drop_user: bool = False) -> Path:
        files = {OWNER: owner, "rust/a/src/user.rs": user if not drop_user else "fn t() {}\n"}
        files.update(extra or {})
        for rel, body in files.items():
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        if chain is not None:
            c = tmp / CHAIN
            c.parent.mkdir(parents=True, exist_ok=True)
            c.write_bytes(chain)
        return tmp

    cases = [
        ("clean", {}, False),
        ("changed chain", {"chain": b"recaptured"}, True),
        ("missing chain", {"chain": None}, True),
        ("new consumer", {"extra": {"rust/b/src/new_tests.rs": "use x::{store_with_prefix};\n"}}, True),
        ("comment is not a consumer", {"extra": {"rust/b/src/doc.rs": "/// see `close_shards`\n"}}, False),
        ("stale reader", {"drop_user": True}, True),
    ]
    failed = 0
    for name, kwargs, want_errors in cases:
        with tempfile.TemporaryDirectory() as d:
            root = tree(Path(d), **kwargs)
            errors = check(root, pinned, readers)
        if bool(errors) != want_errors:
            print(f"selftest FAIL: {name}: errors={errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")
    return failed


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    errors = check(REPO, PINNED_SHA256, READERS)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print(f"PASS: {CHAIN} is frozen at its pinned hash ({PIN_REASON}), and {len(READERS)} listed files read it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
