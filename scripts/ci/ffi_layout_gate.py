#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The struct-layout limb of the FFI signature gate
# (scripts/ci/check_ffi_signatures.sh). A struct crossing the boundary is
# defined twice: #[repr(C)] in Rust and by hand in a C header. C++ reading a
# struct whose fields moved does not fail. It reads support flags out of a
# height. For each pair GROUPS names, this script:
#
#   1. generates the Rust definitions (cbindgen) into one namespace per
#      crate, with the array bounds they name generated from the crates that
#      own them (BOUNDS);
#   2. compares member NAMES, in order, both ways. A member only one side
#      has fails here by name, including one sitting in the other side's
#      padding, which every size and offset would still agree with;
#   3. writes the static_asserts ffi_layout_gate.cpp compiles: size,
#      alignment, and each member's offset and type. Offsets are keyed by
#      name, so two members of one width swapped on one side fail even
#      though the size agrees.
#
# Completeness: every struct a header under src/ defines with the FFI
# prefix (Shekyl..., shekyl_...) is a pair's C side or is EXEMPT with its
# reason, and every pair's C side is defined in its group's headers. A
# struct a .cpp file defines is opaque to Rust, which holds only a pointer.
#
# Usage: ffi_layout_gate.py WORKDIR   (run from the repository root; prints
# the number of pairs compared and of exemptions)

import pathlib
import re
import subprocess
import sys

GROUPS = [
    {
        "crate": "rust/shekyl-ffi/src/lib.rs",
        "namespace": "rust_ffi",
        "headers": ["src/shekyl/shekyl_ffi.h"],
        "bounds": [
            "rust/shekyl-seam/src/endpoint.rs",
            "rust/shekyl-archival-retention/src/pass_anchor.rs",
        ],
        # Its array bounds are aliases of constants in shekyl-crypto-pq and
        # shekyl-address, which alias further constants; see EXEMPT.
        "exclude": ["ShekylAllKeysBlob"],
        "pairs": {
            "ShekylBuffer": "ShekylBuffer",
            "ShekylPqcKeypair": "ShekylPqcKeypair",
            "ShekylPqcSignatureResult": "ShekylPqcSignatureResult",
            "ShekylPqcCanonicalLens": "ShekylPqcCanonicalLens",
            "ShekylBurnSplit": "ShekylBurnSplit",
            "ShekylEmissionSplit": "ShekylEmissionSplit",
            "ShekylOutputData": "ShekylOutputData",
            "ShekylPqcAuthResult": "ShekylPqcAuthResult",
            "ShekylCurveTreeReplicaOutput": "ShekylCurveTreeReplicaOutput",
            "ShekylCurveTreeReplicaTx": "ShekylCurveTreeReplicaTx",
            "ShekylSignResult": "ShekylSignResult",
            "ShekylArchivalVerifyCtx": "shekyl_archival_verify_ctx",
            "ShekylArchivalPidPubkey": "shekyl_archival_pid_pubkey",
            "ShekylArchivalAttestationVerifyCtx": "shekyl_archival_attestation_verify_ctx",
            "ShekylArchivalShardCoverageIn": "ShekylArchivalShardCoverageIn",
            "ShekylArchivalShardCoverageOut": "ShekylArchivalShardCoverageOut",
            "ShekylArchivalEpochCloseBond": "shekyl_archival_epoch_close_bond",
            "ShekylArchivalEpochCloseShard": "shekyl_archival_epoch_close_shard",
            "ShekylArchivalCreditPair": "shekyl_archival_credit_pair",
            "ShekylArchivalEmissionEpochSnapshot": "shekyl_archival_emission_epoch_snapshot",
            "ShekylU128": "shekyl_u128",
            "ShekylRelayBlob": "ShekylRelayBlob",
            "ShekylInboundCeiling": "shekyl_inbound_ceiling",
            "ShekylStemTallyRow": "ShekylStemTallyRow",
            "ShekylSeamAddress": "shekyl_seam_address",
            "ShekylSeamObserved": "shekyl_seam_observed",
            "ShekylSeamOpenResult": "shekyl_seam_open_result",
            "ShekylSeamBoardRow": "shekyl_seam_board_row",
            "ShekylSeamSessionCounts": "shekyl_seam_session_counts_t",
            "ShekylSeamHandshakeResult": "shekyl_seam_handshake_result",
            "ShekylRpcPeerFacts": "shekyl_rpc_peer_facts",
            "ShekylBanView": "shekyl_ban_view",
            "ShekylIngestBlob": "shekyl_ingest_blob",
            "ShekylIngestArrival": "shekyl_ingest_arrival",
            "ShekylIngestReply": "shekyl_ingest_reply",
        },
    },
    {
        # The daemon RPC reads C++ facts through its own twins, some of them
        # of structs shekyl-ffi also defines.
        "crate": "rust/shekyl-daemon-rpc/src/lib.rs",
        "namespace": "rust_daemon_rpc",
        "headers": [
            "src/shekyl/shekyl_ffi.h",
            "src/rpc/rpc_facts_ffi.h",
            "src/rpc/daemon_submit_ffi.h",
        ],
        "bounds": [],
        # Opaque: C++ holds only its pointer, and its members are Rust types.
        "exclude": ["ShekylDaemonRpcHandle"],
        "pairs": {
            "IdentityFactsFfi": "shekyl_rpc_identity_facts",
            "ChainTipFactsFfi": "shekyl_rpc_chain_tip_facts",
            "BlockHashFactsFfi": "shekyl_rpc_block_hash_facts",
            "BlockHeaderFactsFfi": "shekyl_rpc_block_header_facts",
            "BlockPayloadFfi": "shekyl_rpc_block_payload",
            "BlockEntryFfi": "shekyl_rpc_block_entry",
            # `where` is a Rust keyword.
            "TxEntryFfi": ("shekyl_rpc_tx_entry", {"where_found": "where"}),
            "NetStatsFactsFfi": "shekyl_rpc_net_stats_facts",
            "ConnectionFactsFfi": "shekyl_rpc_connection_facts",
            "SyncSpanFactsFfi": "shekyl_rpc_sync_span_facts",
            "FeeEstimateFactsFfi": "shekyl_rpc_fee_estimate_facts",
            "InfoChainFactsFfi": "shekyl_rpc_info_chain_facts",
            "InfoStatusFactsFfi": "shekyl_rpc_info_status_facts",
            "InfoPeersFactsFfi": "shekyl_rpc_info_peers_facts",
            "PeerFactsFfi": "shekyl_rpc_peer_facts",
            "SeamSessionCountsFfi": "shekyl_seam_session_counts_t",
            "SubmitFactsFfi": "shekyl_submit_facts_ffi",
            "SubmitEmissionBondFfi": "shekyl_submit_emission_bond_ffi",
            "SubmitEmissionSnapshotFfi": "shekyl_submit_emission_snapshot_ffi",
            "SubmitEmissionFactsFfi": "shekyl_submit_emission_facts_ffi",
            "SubmitReleaseRecordFfi": "shekyl_submit_release_record_ffi",
            "SubmitReleaseFactsFfi": "shekyl_submit_release_facts_ffi",
            "ArchivalEpochCloseBondFfi": "shekyl_archival_epoch_close_bond",
            "ArchivalEpochCloseShardFfi": "shekyl_archival_epoch_close_shard",
            "ArchivalCreditPairFfi": "shekyl_archival_credit_pair",
        },
    },
    {
        # The daemon's Rust main() hands the C++ remnant its entry and the
        # configuration snapshot the remnant still reads.
        "crate": "rust/shekyl-daemon/src/lib.rs",
        "namespace": "rust_daemon",
        # `run` and `stop` are `Option<RunFn>` and `Option<StopFn>`.
        "item_types": ["structs", "enums", "typedefs"],
        "headers": ["src/shekyl/shekyl_ffi.h"],
        "bounds": [],
        "exclude": [],
        "pairs": {
            "ShekylStringList": "ShekylStringList",
            "ShekylClientEndpoint": "ShekylClientEndpoint",
            "ShekylMineAddress": "ShekylMineAddress",
            "ShekylDaemonSnapshot": "ShekylDaemonSnapshot",
            "ShekylDaemonEntry": "ShekylDaemonEntry",
        },
    },
]

# Structs a header defines that no pair compares, each with its reason.
EXEMPT = {
    "ShekylOwnedBuffer": "C++ only: an RAII owner of a ShekylBuffer; it never crosses",
    "ShekylAllKeysBlob": (
        "its array bounds are shekyl-crypto-pq constants aliasing shekyl-address "
        "constants that alias further ones, the cross-crate limitation the "
        "FOLLOWUPS entry names; its Rust layout is pinned by "
        "struct_layout_matches in account_ffi.rs"
    ),
    "shekyl_close_cause": (
        "CloseKind is declared through a macro, which cbindgen does not expand "
        "on stable; the pair is pinned both ways by the CLOSE_CAUSE_* constants "
        "in shekyl-transport-layer's cause.rs and the header's static_asserts"
    ),
}

CONFIG = "scripts/ci/cbindgen-ffi-layouts.toml"
BOUNDS_CONFIG = "scripts/ci/cbindgen-ffi-bounds.toml"
DEFINITION = re.compile(
    r"^\s*(?:typedef\s+)?struct\s+((?:Shekyl|shekyl_)\w*)\s*(?:\{.*)?$", re.M)


def fail(message):
    sys.exit(f"error: {message}")


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def body_of(text, name):
    """The member text of struct `name`'s definition, or None."""
    match = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{", text)
    if match is None:
        return None
    depth, start = 1, match.end()
    for at in range(start, len(text)):
        if text[at] == "{":
            depth += 1
        elif text[at] == "}":
            depth -= 1
            if depth == 0:
                return text[start:at]
    return None


def members(body, where):
    """Member names in declaration order."""
    names = []
    for decl in body.split(";"):
        decl = " ".join(decl.split())
        if not decl or decl.startswith("static_assert"):
            continue
        # A default initializer is not part of the layout.
        decl = re.split(r"\s*[={]", decl, maxsplit=1)[0]
        if "," in decl:
            fail(f"{where}: '{decl}' declares several members; write one per declaration")
        # A pointer-to-array member: `const uint8_t (*name)[N]`.
        pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", decl)
        if pointer:
            names.append(pointer.group(1))
            continue
        decl = re.sub(r"(\s*\[[^\]]*\])+$", "", decl)
        name = re.search(r"([A-Za-z_]\w*)$", decl)
        if name is None or "(" in decl:
            fail(f"{where}: cannot read a member name from '{decl}'")
        names.append(name.group(1))
    return names


def twin(value):
    """A pair's C name and its member renames, Rust name to C name. A
    rename is for a name one language cannot spell."""
    return (value, {}) if isinstance(value, str) else value


def cbindgen(config_text, source, out, workdir):
    config = workdir / "layout.toml"
    config.write_text(config_text, encoding="utf-8")
    run = subprocess.run(["cbindgen", "--config", str(config), "--output", str(out), source],
                         capture_output=True, text=True)
    if run.returncode != 0:
        sys.stderr.write(run.stderr)
        fail(f"cbindgen failed on {source}")
    return out.read_text(encoding="utf-8")


def main():
    workdir = pathlib.Path(sys.argv[1])
    base = pathlib.Path(CONFIG).read_text(encoding="utf-8")
    bounds_base = pathlib.Path(BOUNDS_CONFIG).read_text(encoding="utf-8")

    # Completeness, both ways, over every header under src/.
    defined = {}
    for header in sorted(pathlib.Path("src").rglob("*.h")):
        for name in DEFINITION.findall(strip_comments(header.read_text(encoding="utf-8"))):
            defined[name] = str(header)
    if not defined:
        fail("found no struct definitions under src/: the pattern is wrong")
    compared = {twin(v)[0] for group in GROUPS for v in group["pairs"].values()}
    unlisted = sorted(set(defined) - compared - set(EXEMPT))
    if unlisted:
        fail("structs a header defines that the layout limb neither compares nor exempts:\n  "
             + "\n  ".join(f"{n} ({defined[n]})" for n in unlisted))
    gone = sorted((compared | set(EXEMPT)) - set(defined))
    if gone:
        fail("the layout limb lists structs no header under src/ defines:\n  " + "\n  ".join(gone))

    rust, twins, asserts, includes, pairs = [], [], [], [], 0
    for group in GROUPS:
        ns = group["namespace"]
        top = f'namespace = "{ns}"\n'
        for bound in group["bounds"]:
            rust.append(cbindgen(top + bounds_base, bound, workdir / "bound.h", workdir))
        include = ", ".join(f'"{r}"' for r in group["pairs"])
        exclude = ", ".join(f'"{r}"' for r in group["exclude"])
        items = ", ".join(f'"{i}"' for i in group.get("item_types", ["structs", "enums"]))
        generated = cbindgen(top + base + f"item_types = [{items}]\n"
                             f"include = [{include}]\nexclude = [{exclude}]\n",
                             group["crate"], workdir / f"{ns}.h", workdir)
        rust.append(generated)
        generated = strip_comments(generated)
        header_text = strip_comments("\n".join(
            pathlib.Path(h).read_text(encoding="utf-8") for h in group["headers"]))
        for header in group["headers"]:
            line = f'#include "{header.removeprefix("src/")}"'
            if line not in includes:
                includes.append(line)
        for r, value in group["pairs"].items():
            c, renames = twin(value)
            rust_body = body_of(generated, r)
            if rust_body is None:
                fail(f"{r} is missing from {group['crate']}'s generated header: "
                     "the struct moved or is no longer #[repr(C)]")
            c_body = body_of(header_text, c)
            if c_body is None:
                fail(f"struct {c} (twin of {r}) has no definition in {group['headers']}")
            rust_members, c_members = members(rust_body, r), members(c_body, c)
            if not rust_members:
                fail(f"{r} generated with no members")
            stale = sorted(set(renames) - set(rust_members))
            if stale:
                fail(f"{r} has no member {', '.join(stale)} to rename")
            if [renames.get(m, m) for m in rust_members] != c_members:
                fail(f"struct {c} does not have the members of {r}, in order:\n"
                     f"  Rust: {' '.join(rust_members)}\n  C++:  {' '.join(c_members)}")
            twins.append(f"template <> struct norm<{ns}::{r}> {{ using type = ::{c}; }};")
            rr, h = f"{ns}::{r}", f"::{c}"
            asserts.append(f'static_assert(sizeof({rr}) == sizeof({h}), "{c} ({r}): size");')
            asserts.append(f'static_assert(alignof({rr}) == alignof({h}), "{c} ({r}): alignment");')
            for m in rust_members:
                cm = renames.get(m, m)
                asserts.append(f"static_assert(offsetof({rr}, {m}) == offsetof({h}, {cm}), "
                               f'"{c}::{cm} ({r}): offset");')
                asserts.append(f"static_assert(ffi_layout_gate::same<decltype({rr}::{m}), "
                               f'decltype({h}::{cm})>, "{c}::{cm} ({r}): type");')
            pairs += 1

    note = "// Generated by scripts/ci/ffi_layout_gate.py.\n"
    (workdir / "shekyl_ffi_layout_c.h").write_text(note + "\n".join(includes) + "\n", encoding="utf-8")
    (workdir / "shekyl_ffi_layout_rust.h").write_text(note + "\n".join(rust), encoding="utf-8")
    (workdir / "shekyl_ffi_layout_asserts.h").write_text(
        note + "namespace ffi_layout_gate {\n" + "\n".join(twins)
        + "\n}  // namespace ffi_layout_gate\n\n" + "\n".join(asserts) + "\n", encoding="utf-8")
    print(f"{pairs} {len(EXEMPT)}")


if __name__ == "__main__":
    main()
