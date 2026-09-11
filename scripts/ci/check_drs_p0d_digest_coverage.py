#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
"""DRS-P0d digest-v0 coverage gate.

P0d's deliverable is a layout-independent logical state digest whose
*minimum* is three families (core chain, spent_keys, live curve-tree
root) and whose *named exclusion* is the archival journals (§7.1.1).
A digest that hashed the wrong tables, or silently dropped one of the
three, would still compile and the C++ tests on a sparse fixture would
not notice.

Instance of `47-gate-subject-assertion.mdc`: the gate asserts its own
subject exists (`pub fn digest_v0` in the crate, the FFI symbol, the
LMDB walker) so an empty or mis-anchored parse fails loudly instead of
passing vacuously over nothing.

This gate does NOT recompute cSHAKE (that is `shekyl-crypto-hash` plus
the crate's property tests). It asserts the three families are named
at every layer that claims to implement v0, and that the archival
exclusion is written at those same layers.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIGEST_RS = ROOT / "rust" / "shekyl-chain-store" / "src" / "digest_v0.rs"
WALKER_CPP = ROOT / "src" / "blockchain_db" / "lmdb" / "logical_state_digest.cpp"
FFI_RS = ROOT / "rust" / "shekyl-ffi" / "src" / "chain_digest_ffi.rs"
FFI_H = ROOT / "src" / "shekyl" / "shekyl_ffi.h"
AUDIT = ROOT / "docs" / "LMDB_WRITE_ATOMICITY_AUDIT.md"

# Subject-assertion floors: the files held at least this many bytes when
# the gate was written. A parse yielding a truncated stub is a broken
# subject, not a pass.
MIN_DIGEST_RS = 2000
MIN_WALKER_CPP = 800


def must_read(path: pathlib.Path) -> str:
    if not path.is_file():
        sys.exit(f"FAIL: subject missing: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        sys.exit(f"FAIL: subject empty: {path.relative_to(ROOT)}")
    return text


def require(cond: bool, msg: str) -> None:
    if not cond:
        sys.exit(f"FAIL: {msg}")


def main() -> None:
    digest = must_read(DIGEST_RS)
    walker = must_read(WALKER_CPP)
    ffi_rs = must_read(FFI_RS)
    ffi_h = must_read(FFI_H)
    audit = must_read(AUDIT)

    require(len(digest) >= MIN_DIGEST_RS,
            f"{DIGEST_RS.name} is {len(digest)} bytes "
            f"(floor {MIN_DIGEST_RS}) — broken parse or emptied subject")
    require(len(walker) >= MIN_WALKER_CPP,
            f"{WALKER_CPP.name} is {len(walker)} bytes "
            f"(floor {MIN_WALKER_CPP}) — broken parse or emptied subject")

    require("pub fn digest_v0" in digest,
            "digest_v0.rs does not define pub fn digest_v0")
    require("DIGEST_PREIMAGE_LEN: usize = 1 + 8 + 8 + 32 + 32 + 32" in digest,
            "digest_v0.rs PREIMAGE_LEN does not match the documented 113-byte layout")
    require('b"shekyl/chain-digest/v0"' in digest,
            "outer customization shekyl/chain-digest/v0 missing")
    require('b"shekyl/chain-digest/v0/chain"' in digest,
            "chain customization missing")
    require('b"shekyl/chain-digest/v0/spent-elem"' in digest,
            "spent-elem customization missing")

    for token in ("spent_keys", "block_info", "get_curve_tree_root"):
        require(token in digest,
                f"digest_v0.rs does not name v0 family token {token!r}")

    require("§7.1.1" in digest and "archival" in digest.lower(),
            "digest_v0.rs does not record the §7.1.1 archival exclusion")

    require("get_block_hash_from_height" in walker,
            "LMDB walker does not read core-chain hashes")
    require("for_all_key_images" in walker,
            "LMDB walker does not read spent_keys")
    require("get_curve_tree_root" in walker,
            "LMDB walker does not read the live curve-tree root")
    require("shekyl_logical_state_digest_v0" in walker,
            "LMDB walker does not call the Rust hasher")
    require("block_rtxn_start" in walker,
            "LMDB walker does not hold one snapshot for the three families")

    require("shekyl_logical_state_digest_v0" in ffi_rs,
            "FFI rust export shekyl_logical_state_digest_v0 missing")
    require("shekyl_logical_state_digest_v0" in ffi_h,
            "FFI header shekyl_logical_state_digest_v0 missing")

    # P0b leftover: the digest's inputs are the RAW read set. The audit
    # must name the three v0 families as digest reads so a later writer
    # cannot add a write path that the digest does not observe.
    require(re.search(r"Digest v0 read set", audit),
            "LMDB_WRITE_ATOMICITY_AUDIT.md has no 'Digest v0 read set' section")
    for token in ("spent_keys", "block_info", "get_curve_tree_root"):
        require(token in audit,
                f"audit digest-v0 read set does not name {token!r}")

    print("PASS: DRS-P0d digest v0 names core chain, spent_keys, curve root; "
          "archival journals excluded; walker/FFI/audit agree")


if __name__ == "__main__":
    main()
