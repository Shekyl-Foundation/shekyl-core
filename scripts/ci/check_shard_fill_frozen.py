#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The shard-fill chain is frozen, and it takes no new consumers.

# What is held

`CHAIN_FORGE.md` `CF-R17` (Rick, 2026-11-13): the checked-in shard-fill
chain (`rust/shekyl-harness-spender/vectors/shard-fill.bin`) stays exactly
as it is until `CF-4a` (`CF-R23`) replaces it with a forged chain and deletes it. Its
bytes do not regenerate (proving draws fresh randomness), so every
re-capture would add another 11.5 MB to the repository's history for
good. And nothing new may come to depend on it: a new test that wants a
chain at that scale waits for the forge.

  1. **Frozen.** The file exists and its SHA-256 is `PINNED_SHA256`.
  2. **No new consumer.** Outside comments, a line that names one of the
     chain's access points (`ACCESS`: the type's loader, its path, its
     reserved-coinbase count, and the ingest's and the store's prefix
     helpers built on it) is counted under the function it sits in
     (`<module>` before the file's first `fn`). Every (file, function)
     pair with a count must be in `READERS`, at no more than its pinned
     count. So a new test that calls a helper fails, whether it is in a
     new file or in a file already listed, and so does an extra access
     added to a listed function.
  3. **The list only shrinks.** Every pinned pair still has exactly its
     pinned count. One that dropped is lowered, or taken off when it
     reaches zero, in the change that moves the consumer, so `READERS` is
     also `CF-4a`'s migration list (`CHAIN_FORGE.md` §12.1, `CF-4a`).

What this does not see: an access moved from one line to another inside
the same function, at the same count, or a helper renamed so that no
`ACCESS` pattern names it. Review covers those; the gate covers growth.

# A consensus change that would invalidate the chain

`CF-R20`: the normal path is that `CF-4a`'s replacement lands first. If such
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
FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+(\w+)")
MODULE = "<module>"

# The chain's owner, its two readers, and their consumers at the freeze
# (`bfdc84a30` plus #1370): file -> function -> access lines. Lowering a
# count, or removing an entry, is how a consumer leaves; raising one or
# adding one needs a ruling that reopens `CF-R17`.
READERS: dict[str, dict[str, int]] = {
    # The owner: the format, the loader and the path.
    "rust/shekyl-harness-spender/src/captured.rs": {
        MODULE: 1,
        "shard_fill_path": 2,
        "shard_fill": 1,
    },
    # The ingest's reader (`load_shard_fill`, `close_shards`) and its users.
    "rust/shekyl-chain-ingest/src/scenario_shard.rs": {
        "settled_schedule": 1,
        "load_shard_fill": 2,
        "close_shards": 1,
    },
    "rust/shekyl-chain-ingest/src/archival_pop_roundtrip_tests.rs": {
        MODULE: 1,
        "a_claim_chain_pops_and_reconnects_at_every_block_from_the_joins_on": 1,
        "a_popped_claim_restores_the_epoch_its_prune_dropped_and_a_second_claim_is_refused": 1,
    },
    "rust/shekyl-chain-ingest/src/archival_slash_tests.rs": {
        MODULE: 1,
        "open": 1,
    },
    "rust/shekyl-chain-ingest/src/bundle_producer_gate_tests.rs": {
        MODULE: 1,
        "a_produced_bundle_is_admitted_and_connects_through_the_staged_door": 1,
        "a_produced_support_bundle_is_admitted_and_connects_through_the_staged_door": 1,
    },
    "rust/shekyl-chain-ingest/src/pool_submit_tests.rs": {
        "closed_shards_lane": 2,
    },
    "rust/shekyl-chain-ingest/src/rpc_store_facts_tests/below_horizon.rs": {
        MODULE: 1,
        "the_wallet_and_the_rpc_read_a_spend_whose_shard_the_store_discarded": 1,
    },
    "rust/shekyl-chain-ingest/src/scenario_emission_tests.rs": {
        MODULE: 1,
        "the_drivers_emission_claim_connects_and_pays_the_persona": 1,
        "a_claim_verifies_after_the_epochs_complete_trees_are_released_and_slashed": 1,
    },
    "rust/shekyl-chain-ingest/src/scenario_join_tests.rs": {
        MODULE: 1,
        "a_join_is_written_and_the_blocks_after_it_read_the_record": 1,
    },
    # The store's reader (`store_with_prefix`, the capture writer) and its
    # users.
    "rust/shekyl-chain-store/src/store/shard_fill.rs": {
        MODULE: 1,
        "shard_fill": 1,
        "write_capture": 2,
        "store_with_prefix": 1,
    },
    "rust/shekyl-chain-store/src/store/prune_tests.rs": {
        MODULE: 1,
        "captured": 1,
        "chain_to_400": 1,
        "the_boundary_batch_discards_closed_shards_on_real_spends": 4,
        "short_captured": 1,
        "the_predicate_survives_a_prune_on_the_stored_rows": 1,
    },
    "rust/shekyl-chain-store/src/store/slash_scan_bench_tests.rs": {
        "prefix": 1,
        "build_under": 1,
    },
}
OWNER = "rust/shekyl-harness-spender/src/captured.rs"


def access_counts(text: str) -> dict[str, int]:
    """Access lines outside comments, by the function they sit in."""
    counts: dict[str, int] = {}
    current = MODULE
    for line in text.splitlines():
        found = FN_RE.match(line)
        if found:
            current = found.group(1)
        if line.lstrip().startswith("//"):
            continue
        if ACCESS_RE.search(line):
            counts[current] = counts.get(current, 0) + 1
    return counts


def rust_sources(root: Path) -> list[Path]:
    return sorted(p for p in (root / "rust").rglob("*.rs") if "/target/" not in p.as_posix())


def check(root: Path, pinned: str, readers: dict[str, dict[str, int]]) -> list[str]:
    errors: list[str] = []
    if not PIN_REASON.strip():
        errors.append("PIN_REASON is empty: a pin names why it is this hash (CF-R20)")

    chain = root / CHAIN
    if not chain.is_file():
        return errors + [f"{CHAIN} is missing: the freeze has no subject (CF-R17 ends only in CF-4a)"]
    digest = hashlib.sha256(chain.read_bytes()).hexdigest()
    if digest != pinned:
        errors.append(
            f"{CHAIN} changed (sha256 {digest}, pinned {pinned}). The chain is frozen until "
            "CF-4a (CHAIN_FORGE.md CF-R17, CF-R23): its bytes do not regenerate, so a re-capture adds "
            "11.5 MB to history for good. Restore the file. If a consensus change must land "
            "before CF-4a's replacement, Rick approves one re-capture explicitly, and the pin "
            "update changes PINNED_SHA256 and PIN_REASON together, citing it (CF-R20). The "
            "tests are never turned off."
        )

    sources = rust_sources(root)
    if not sources:
        return errors + ["no Rust source under rust/: the scan has no subject"]

    found: dict[str, dict[str, int]] = {}
    for path in sources:
        counts = access_counts(path.read_text(encoding="utf-8", errors="replace"))
        if counts:
            found[path.relative_to(root).as_posix()] = counts

    if OWNER not in found:
        errors.append(f"{OWNER} names none of the access points: the scan matches nothing")

    new = (
        "a new consumer of the frozen shard-fill chain. Nothing new depends on it "
        "(CHAIN_FORGE.md CF-R17); a chain at that scale waits for the forge."
    )
    for rel, counts in sorted(found.items()):
        pins = readers.get(rel)
        for function, count in sorted(counts.items()):
            pin = None if pins is None else pins.get(function)
            if pin is None:
                errors.append(f"{rel}: `{function}` reads the chain ({count} access line(s)): {new}")
            elif count > pin:
                errors.append(
                    f"{rel}: `{function}` has {count} access lines, pinned at {pin}: {new}"
                )

    for rel, pins in readers.items():
        counts = found.get(rel, {})
        if not (root / rel).is_file():
            errors.append(f"{rel} is in READERS and does not exist: take it off the list")
            continue
        for function, pin in pins.items():
            count = counts.get(function, 0)
            if count < pin:
                errors.append(
                    f"{rel}: `{function}` is pinned at {pin} access lines and has {count}: "
                    "lower the pin, or take it off at zero (CF-4a's list only shrinks)"
                )
    return errors


def selftest() -> int:
    good = b"frozen chain bytes"
    pinned = hashlib.sha256(good).hexdigest()
    owner = "pub fn shard_fill_path() -> PathBuf { todo!() }\n"
    user = "use x::close_shards;\n\nfn listed_test() {\n    let x = close_shards(&mut s, 1);\n}\n"
    readers = {
        OWNER: {"shard_fill_path": 1},
        "rust/a/src/user.rs": {MODULE: 1, "listed_test": 1},
    }

    def tree(tmp: Path, *, chain: bytes | None = good, files: dict[str, str] | None = None) -> Path:
        body = {OWNER: owner, "rust/a/src/user.rs": user}
        body.update(files or {})
        for rel, text in body.items():
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        if chain is not None:
            c = tmp / CHAIN
            c.parent.mkdir(parents=True, exist_ok=True)
            c.write_bytes(chain)
        return tmp

    cases = [
        ("clean", {}, False),
        ("changed chain", {"chain": b"recaptured"}, True),
        ("missing chain", {"chain": None}, True),
        ("new consumer in a new file", {"files": {"rust/b/src/new_tests.rs": "fn t() { store_with_prefix(p); }\n"}}, True),
        (
            "new consumer in a listed file",
            {"files": {"rust/a/src/user.rs": user + "\nfn another_test() {\n    load_shard_fill(&mut s, 1);\n}\n"}},
            True,
        ),
        (
            "an extra access in a listed function",
            {"files": {"rust/a/src/user.rs": user.replace("close_shards(&mut s, 1);", "close_shards(&mut s, 1);\n    close_shards(&mut s, 2);")}},
            True,
        ),
        (
            "a comment is not a consumer",
            {"files": {"rust/b/src/doc.rs": "/// see `close_shards`\nfn f() {}\n"}},
            False,
        ),
        (
            "an access that left keeps its pin",
            {"files": {"rust/a/src/user.rs": "use x::close_shards;\n\nfn listed_test() {}\n"}},
            True,
        ),
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
    sites = sum(len(pins) for pins in READERS.values())
    print(
        f"PASS: {CHAIN} is frozen at its pinned hash ({PIN_REASON}); "
        f"{len(READERS)} files, {sites} (file, function) sites read it, none beyond its pin"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
