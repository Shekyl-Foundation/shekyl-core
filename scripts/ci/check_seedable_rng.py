#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""No seedable generator is built in production code unless its site is listed.

# What is held

`CHAIN_FORGE.md` §5.5, `CF-R9` and `CF-R12` (Rick, 2026-11-12). A seedable
generator constructed in production code — `from_seed`, `seed_from_u64`,
`from_rng`, and a crate's own seeded constructors (`keygen_from_seed`,
`keypair_from_seeds` and their kin) — is red unless its **site** is listed
in `SITES`: by path and function, with its group and one line on where its
seed comes from. A group's name allows nothing on its own. The groups, and
the only seed sources the list accepts:

- **G0** — drawn from `OsRng` on the spot.
- **G1** — the output of a key-derivation function over a secret key or
  seed: determinism is the point (the same seed must give the same keys).
- **G2** — verifier batch weights from a domain-separated transcript: weights
  only, never a value that is published or signed.
- **G3** — multisig values every participant derives identically, from a
  transcript that already binds every participant's commitments.

**Always refused, at any signing or proving nonce:** a constant seed, a seed
the caller chooses, or a seed built from public data alone. A fixed seed
exists only through the test-only `seeded-rng` features (§5.3), whose code
this gate does not read.

**No grandfathering.** Every site is listed with its justification. A later
site needs a reviewed change to the list. The list keys on path and
function, so a file move drops a site's listing and sends it back to review,
on purpose. A site's count of constructions is pinned too, so a second
construction in a listed function is reviewed like a new site.

# What is production code

The crates the shipped binaries build (`CF-R26`, Rick, 2026-11-15): the
set `shipped_graph.py` computes, which `check_production_graph.py` reads
too. It is this repository's release (`cmake/BuildRust.cmake`'s roots in
one invocation, with the release's features, every platform's
`[target.*]` tables) and the GUI wallet's release (its pinned shekyl-core
edges). A crate enters when either build activates it, and its sites are
checked from the commit it enters: there is no list of crates to update.
`shekyl-harness-wallet` and `shekyl-randomx-differential` are outside by
construction (the gate asserts both).

Crates headed for production are read now (`CF-R26`): the members
`shipped_graph.HEADED_FOR_PRODUCTION` lists (they will ship; no shipped
build links them yet), so a seeded site in one is reviewed before a release
links it. A headed crate already in the set is refused: it leaves the list
in the change that links it.

Within a crate in the set, its whole `src/` tree is read, less the items
under a cfg that holds only in a test build: `test`, or a feature
`check_test_only_features.py` registers as TEST_ONLY for that crate (its
`TEST_ONLY` table, read here so the two never drift). A feature the
release leaves off but that is not test-only (`shekyl-fcmp`'s `multisig`)
is read: it is production code a wallet turns on. The reading of cfgs, and
of files declared as modules under one, is `check_network_uniformity.py`'s,
imported. Test, bench and example targets live outside `src/` and are not
read.

# Provisional listings

A listing whose seed source is promised by a named, not-yet-landed
increment carries a marker in `PROVISIONAL`: the increment, and the domain
label that increment registers in `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`
with the code that derives under it. Once that label is registered, the
increment has landed, and a marker still present is red: the listing must
be restated for the code as landed and the marker removed. A marker has an
expiry; it cannot sit forever.

# Test-only sites

`TEST_ONLY_SITES` names functions that must stay in test-only code: a seeded
signer that exists so a fixture or the chain forge can sign without the OS
(`CF-R16`: the driver's receipt stand-in). The gate fails if one is no longer
found, or is found in production code.

# Rule 47

The gate asserts its subject: it reads members' sources and finds at least
one listed site live. `--selftest` plants an unlisted `seed_from_u64` in
production code (red), one under a test-only cfg (green), a listed site at a
moved path (red), a row for code that is gone (red), and a test-only site
that has moved into production (red), and a provisional marker whose
increment has landed (red). Through the path `main()` runs (manifests, the
set, the scan), it plants a seeded site in a crate outside the graph
(green), then adds that crate as a shipped binary's or the GUI wallet's
dependency (red), or lists it headed for production (red). `--list` prints
every production site it finds, the census the list is reviewed against.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_network_uniformity import (  # noqa: E402
    drop_test_items,
    strip,
    test_file_closure,
    test_only_features,
)
from shipped_graph import (  # noqa: E402
    HEADED_FOR_PRODUCTION,
    GraphError,
    graphs,
    live_graphs,
    member_dirs,
    shipped_crates,
)

REPO = Path(__file__).resolve().parents[2]
RUST = REPO / "rust"

# A seedable generator's construction. A definition (`fn from_seed`) is not
# one; the scan skips a match preceded by `fn`.
CONSTRUCTION = re.compile(
    r"(?<![\w])(?<!fn )(?:from_seed|seed_from_u64|from_rng|keygen_from_seed\w*|keypair_from_seeds?)\s*\("
)
FN = re.compile(r"\bfn\s+(\w+)")
# Cheap prefilters on the raw text, so only the files that can hold a site,
# or declare a module under a cfg, pay for the full reading.
RAW_CONSTRUCTION = re.compile(
    r"(?:from_seed|seed_from_u64|from_rng|keygen_from_seed|keypair_from_seed)\w*\s*\("
)
MODULE = "<module>"
GROUPS = ("G0", "G1", "G2", "G3")

# (path under rust/, function) -> (group, constructions, where the seed comes from)
SITES: dict[tuple[str, str], tuple[str, int, str]] = {
    # G0: drawn from the OS on the spot.
    ("shekyl-crypto-pq/src/fn_dsa_hybrid.rs", "generate_keypair"): (
        "G0", 1, "both 32-byte key seeds are fresh OS bytes (key_material32) drawn just before"),
    ("shekyl-fcmp/src/frost_sal.rs", "algorithm"): (
        "G0", 1, "a ChaCha20 seed filled from OsRng on the spot; it only weights the batch "
        "check of the aggregate signature and never reaches a nonce (CF-F14)"),
    ("shekyl-onion-key/src/lib.rs", "ephemeral"): (
        "G0", 1, "an onion key's seed filled from OsRng on the spot"),
    # G1: the output of a key derivation over a secret seed or key.
    ("shekyl-crypto-pq/src/account.rs", "ml_kem_keypair_from_d_z"): (
        "G1", 1, "ML-KEM's (d, z), derived from the wallet's master seed"),
    ("shekyl-crypto-pq/src/archival_p.rs", "build_hybrid"): (
        "G1", 1, "the persona's ML-DSA seed, derived from the wallet's master seed"),
    ("shekyl-crypto-pq/src/archival_p.rs", "derive_archival_p_keys"): (
        "G1", 1, "the receipt key's Ed25519 and FN-DSA seeds, derived from the master seed"),
    ("shekyl-crypto-pq/src/archival_p.rs", "derive_p_onion_keypair"): (
        "G1", 1, "the persona's onion seed, derived from the master seed"),
    ("shekyl-crypto-pq/src/derivation.rs", "derive_pqc_public_key"): (
        "G1", 1, "the output's ML-DSA seed, derived from its combined shared secret"),
    ("shekyl-crypto-pq/src/derivation.rs", "hybrid_keypair_from_seed"): (
        "G1", 1, "a multisig member's per-output or envelope seed, derived by its caller "
        "from the member's secrets"),
    ("shekyl-crypto-pq/src/derivation.rs", "keygen_from_seed"): (
        "G1", 1, "ML-DSA keygen from a derived seed (FIPS 204 Algorithm 1, deterministic "
        "by design); every caller passes a key derivation's output"),
    ("shekyl-crypto-pq/src/fn_dsa_hybrid.rs", "fn_dsa_keygen"): (
        "G1", 1, "FN-DSA keygen from a seed its callers derive (or, in generate_keypair, "
        "draw from the OS)"),
    ("shekyl-crypto-pq/src/multisig_intent.rs", "rng"): (
        "G1", 1, "a multisig input's rerandomization seed (RerandomizationSeed): the blinds "
        "r_o, r_i, r_r_i that shekyl-fcmp's SalSigningParams::new draws from this stream, "
        "never a signing nonce. Made only by IntentSeed::rerandomization_seed, per input in "
        "the intent's input order, by HKDF under shekyl/multisig-intent-rerandomize-v1 from "
        "the intent's group-secret seed (PQC_MULTISIG.md §9.5); no caller passes one in"),
    ("shekyl-crypto-pq/src/output.rs", "construct_output_with_label_plaintext"): (
        "G1", 1, "the output's ML-DSA seed, derived from the transaction secret's shared secret"),
    ("shekyl-crypto-pq/src/output.rs", "keygen_from_seed_bytes"): (
        "G1", 1, "ML-DSA keygen from an output's derived seed"),
    ("shekyl-crypto-pq/src/output.rs", "scan_output_recover_with_ml_kem_dk"): (
        "G1", 1, "the scanned output's ML-DSA seed, derived from the decapsulated secret"),
    ("shekyl-crypto-pq/src/output.rs", "scan_output_with_ml_kem_dk"): (
        "G1", 1, "the scanned output's ML-DSA seed, derived from the decapsulated secret"),
    ("shekyl-crypto-pq/src/output.rs", "sign_derived_output_auth"): (
        "G1", 1, "the spend key's ML-DSA seed, derived from the combined shared secret; the "
        "signature itself is hedged (OS randomness)"),
    # G2: verifier batch weights from a domain-separated transcript.
    ("shekyl-bulletproofs/src/derived.rs", "verify_batch"): (
        "G2", 1, "batch_weights_seed over the batch's own proofs; weights only"),
    ("shekyl-fcmp/src/batch_weights.rs", "rng"): (
        "G2", 1, "cSHAKE256(domain, preimage)[..32] over every value the verify reads; "
        "weights only"),
    # G3: multisig values every participant derives identically.
    ("shekyl-fcmp-proofs/src/sal/multisig.rs", "sign_share"): (
        "G3", 1, "transcript.rng_seed(b\"deterministic_nonces\") derives alpha, beta, delta, "
        "mu, r_z, r_p, r_r_p, parameters not secret within the group. Condition (a): the "
        "threshold secret y's nonce is FROST's, never this stream "
        "(tests/sal/multisig.rs, the_y_share_takes_its_nonce_from_frost_never_from_the_"
        "transcript). Condition (b): before sign_share, modular-frost 0.11.0's sign() binds "
        "every included participant's index, preprocess commitments (commitment_D and "
        "commitment_E of every nonce) and addendum into this transcript, then the merged rho "
        "challenge (src/sign.rs:325-357, :373-377; sign_share at :398), so no derived value "
        "repeats across signing sessions"),
}

REGISTRY = REPO / "docs" / "design" / "CRYPTO_DOMAIN_REGISTRY.tsv"

# (path under rust/, function) -> (the increment that replaces the listing's
# seed source, the domain label that increment registers in REGISTRY). The
# label registered means the increment has landed, and the marker is red.
PROVISIONAL: dict[tuple[str, str], tuple[str, str]] = {}

# (path under rust/, function) -> why it must stay test-only
TEST_ONLY_SITES: dict[tuple[str, str], str] = {
    ("shekyl-chain-rules/src/harness/bundle.rs", "signed_record"): (
        "the driver's receipt stand-in (CHAIN_FORGE.md CF-R16): it signs a pass "
        "record over a fixed delivery digest, so it must never sign anything in a "
        "release build; it lives behind shekyl-chain-rules' TEST_ONLY harness feature"
    ),
}


# Members the ruling names as outside the shipped set, asserted so a change
# that pulls one in is seen (CF-R26).
OUTSIDE = ("shekyl-harness-wallet", "shekyl-randomx-differential")
# A member every shipped wallet links: the set must hold it (rule 47).
INSIDE = "shekyl-crypto-pq"


def production_crates(
    dirs: dict[str, Path], shipped: set[str], headed: dict[str, str]
) -> list[tuple[str, Path]]:
    """(crate name, its `src/`) for every member in the shipped set or
    headed for production."""
    return [
        (name, path / "src")
        for name, path in sorted(dirs.items())
        if (name in shipped or name in headed) and (path / "src").is_dir()
    ]


def headed_errors(shipped: set[str], headed: dict[str, str], members: set[str]) -> list[str]:
    errors = []
    for name in sorted(headed):
        if name in shipped:
            errors.append(
                f"{name} is listed headed for production and a shipped build now links it: "
                "it leaves HEADED_FOR_PRODUCTION (shipped_graph.py) in the change that links it"
            )
        if name not in members:
            errors.append(f"{name} is listed headed for production and is not a member")
    return errors


def registered_labels(text: str) -> set[str]:
    """The domain labels REGISTRY registers (its second column)."""
    labels = set()
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) > 1:
            labels.add(cols[1])
    return labels


def provisional_errors(
    listed: dict[tuple[str, str], tuple[str, int, str]],
    provisional: dict[tuple[str, str], tuple[str, str]],
    labels: set[str],
) -> list[str]:
    errors = []
    for key, (increment, label) in sorted(provisional.items()):
        path, function = key
        if key not in listed:
            errors.append(f"{path} `{function}`: a provisional marker for a site that is not listed")
        elif "PROVISIONAL" not in listed[key][2]:
            errors.append(f"{path} `{function}`: provisional, and its listing does not say so")
        if label in labels:
            errors.append(
                f"{path} `{function}`: provisional until {increment}, which has landed ({label} "
                "is registered in CRYPTO_DOMAIN_REGISTRY.tsv). Restate the listing for the code "
                "as landed and remove its PROVISIONAL marker"
            )
    for key, (_, _, note) in sorted(listed.items()):
        if "PROVISIONAL" in note and key not in provisional:
            errors.append(f"{key[0]} `{key[1]}`: says PROVISIONAL with no marker naming its expiry")
    return errors


def enclosing(code: str, at: int) -> str:
    """The function a position sits in: the last `fn` before it."""
    names = [m.group(1) for m in FN.finditer(code[:at])]
    return names[-1] if names else MODULE


def scan_crate(
    src: Path, features: set[str], root: Path, watched: set[str], hunt: set[str]
) -> tuple[dict, set, set, int]:
    """(production sites, test-only functions, production functions, files
    read) for one crate's `src/`. Sites are keyed `(path, function)` with
    their construction count. Test-only functions and production functions
    are keyed the same way: a name present in the file and absent from its
    production view is test-only, and a name in that view is production.
    Only the files that can hold a site, or a watched (test-only) path, are
    read in full; `watched` is those paths."""
    files = sorted(src.rglob("*.rs"))
    texts = {f: f.read_text(encoding="utf-8", errors="replace") for f in files}
    # Files that are test code whole: declared under a test-only cfg, or
    # below such a module by any path (`check_network_uniformity.py`).
    excluded = test_file_closure(files, features)
    sites: dict[tuple[str, str], int] = {}
    tested: set[tuple[str, str]] = set()
    defined: set[tuple[str, str]] = set()
    for f, raw in texts.items():
        rel = f.relative_to(root).as_posix()
        hunted = any(re.search(rf"\bfn\s+{re.escape(name)}\b", raw) for name in hunt)
        if rel not in watched and not RAW_CONSTRUCTION.search(raw) and not hunted:
            continue
        resolved = f.resolve()
        stripped = strip(raw)
        whole_file_test = resolved in excluded
        production = "" if whole_file_test else drop_test_items(stripped, raw, features)
        # Functions present in the file but absent from its production view
        # are test-only. Names that survive in the production view are the
        # ones a test-only site must not become.
        prod_fns = {m.group(1) for m in FN.finditer(production)}
        for name in prod_fns:
            defined.add((rel, name))
        for m in FN.finditer(stripped):
            if m.group(1) not in prod_fns:
                tested.add((rel, m.group(1)))
        for m in CONSTRUCTION.finditer(production):
            key = (rel, enclosing(production, m.start()))
            sites[key] = sites.get(key, 0) + 1
    return sites, tested, defined, len(files)


def scan(
    root: Path,
    crates: list[tuple[str, Path]],
    features: dict[str, set[str]],
    watched: set[str] | None = None,
    hunt: set[str] | None = None,
):
    sites: dict[tuple[str, str], int] = {}
    tested: set[tuple[str, str]] = set()
    defined: set[tuple[str, str]] = set()
    files = 0
    watched = watched or set()
    hunt = hunt or set()
    for name, src in crates:
        s, t, d, n = scan_crate(src, features.get(name, set()), root, watched, hunt)
        sites.update(s)
        tested.update(t)
        defined.update(d)
        files += n
    return sites, tested, defined, files


def check(
    sites: dict[tuple[str, str], int],
    tested: set[tuple[str, str]],
    defined: set[tuple[str, str]],
    listed: dict[tuple[str, str], tuple[str, int, str]],
    test_only_sites: dict[tuple[str, str], str],
) -> list[str]:
    errors: list[str] = []
    for key, (group, count, note) in sorted(listed.items()):
        path, function = key
        if group not in GROUPS:
            errors.append(f"{path} `{function}`: group {group!r} is not one of {GROUPS} (CF-R12)")
        if not note.strip():
            errors.append(f"{path} `{function}`: a listing names where its seed comes from")
        live = sites.get(key, 0)
        if live == 0:
            errors.append(
                f"{path} `{function}` is listed and builds no seedable generator there: "
                "a row must name live code (a moved file drops its listing; review it again)"
            )
        elif live != count:
            errors.append(
                f"{path} `{function}`: {live} construction(s), listed as {count}: "
                "a new construction is reviewed like a new site; a removed one lowers the count"
            )
    for key, live in sorted(sites.items()):
        if key not in listed:
            path, function = key
            errors.append(
                f"{path} `{function}`: a seedable generator built in production code "
                f"({live} construction(s)) and not listed. List it with its group "
                "(G0 OS on the spot, G1 key derivation, G2 batch weights, G3 multisig "
                "transcript) and its seed's source, or move it under a test-only cfg. "
                "A constant, caller-chosen or public-only seed at a nonce is refused (CF-R12)"
            )
    for key, why in sorted(test_only_sites.items()):
        path, function = key
        if key in tested:
            continue
        errors.append(
            f"{path} `{function}` must stay in test-only code ({why}), and "
            + (
                "is in production code"
                if key in defined
                else "is not found in test-only code"
            )
        )
    return errors


def selftest() -> int:
    features = {"harness"}
    prod = "pub fn keys(seed: [u8; 32]) {\n    let r = ChaCha20Rng::from_seed(seed);\n}\n"
    unlisted = "pub fn bad() {\n    let r = ChaCha20Rng::seed_from_u64(7);\n}\n"
    gated = '#[cfg(test)]\nmod tests {\n    fn t() { let r = ChaCha20Rng::seed_from_u64(7); }\n}\n'
    harness = '#[cfg(feature = "harness")]\npub fn stand_in() { sign(); }\n'
    leaked = "pub fn stand_in() { sign(); }\n"

    def run(files: dict[str, str], listed: dict, test_only_sites: dict) -> list[str]:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "c" / "src"
            for rel, text in files.items():
                p = src / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            sites, tested, defined, _ = scan(
                root, [("c", src)], {"c": features}, {p for p, _ in test_only_sites},
                {name for _, name in test_only_sites},
            )
        return check(sites, tested, defined, listed, test_only_sites)

    key = ("c/src/lib.rs", "keys")
    row = {key: ("G1", 1, "a KDF's output")}
    cases = [
        ("listed site: green", {"lib.rs": prod}, row, {}, False),
        ("unlisted seed_from_u64 in production: red", {"lib.rs": prod + unlisted}, row, {}, True),
        ("under cfg(test): green", {"lib.rs": prod + gated}, row, {}, False),
        ("listed site moved to another file: red", {"keys.rs": prod}, row, {}, True),
        ("row for code that is gone: red", {"lib.rs": "pub fn keys() {}\n"}, row, {}, True),
        ("a second construction in a listed function: red",
         {"lib.rs": prod.replace("}\n", "    let s = ChaCha20Rng::from_seed(seed);\n}\n", 1)}, row, {}, True),
        ("a group that is not G0..G3: red", {"lib.rs": prod}, {key: ("G9", 1, "x")}, {}, True),
        ("test-only site under a TEST_ONLY feature: green",
         {"lib.rs": prod + harness}, row, {("c/src/lib.rs", "stand_in"): "why"}, False),
        ("a #[path] child of a test module: green",
         {"lib.rs": prod + "#[cfg(test)]\nmod a_tests;\n",
          "a_tests.rs": '#[path = "b_tests.rs"]\nmod b;\n',
          "b_tests.rs": unlisted}, row, {}, False),
        ("a sibling under tests/mod.rs: green",
         {"lib.rs": prod + "#[cfg(test)]\nmod tests;\n",
          "tests/mod.rs": "mod fold;\n",
          "tests/fold.rs": unlisted}, row, {}, False),
        ("the same file declared from production: red",
         {"lib.rs": prod + "mod b;\n", "b.rs": unlisted}, row, {}, True),
        ("test-only site moved into production: red",
         {"lib.rs": prod + leaked}, row, {("c/src/lib.rs", "stand_in"): "why"}, True),
    ]
    failed = 0
    for name, files, listed, test_only_sites, want in cases:
        errors = run(files, listed, test_only_sites)
        if bool(errors) != want:
            print(f"selftest FAIL: {name}: {errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")

    moved = run(
        {"lib.rs": prod + leaked}, row, {("c/src/lib.rs", "stand_in"): "why"}
    )
    if not any("is in production code" in e for e in moved):
        print(f"selftest FAIL: a site moved into production did not say so: {moved}")
        failed = 1
    else:
        print("selftest ok: a test-only site moved into production says so")
    gone = run({"lib.rs": prod}, row, {("c/src/lib.rs", "stand_in"): "why"})
    if not any("is not found in test-only code" in e for e in gone):
        print(f"selftest FAIL: a deleted test-only site did not say so: {gone}")
        failed = 1
    else:
        print("selftest ok: a deleted test-only site says it is not found")

    # A crate entering the shipped graph is checked from that commit: the
    # path main() runs (manifests -> the set -> scan -> check), with a
    # seeded site planted in a crate outside the graph, then that crate
    # added as a dependency of a shipped binary, or of the GUI wallet.
    def manifest(name: str, deps: dict) -> dict:
        return {"package": {"name": name}, "dependencies": deps, "features": {}}

    def through_the_graph(members: dict[str, dict], pin: dict, headed: dict) -> list[str]:
        sources = {"lib": prod, "outside": unlisted}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dirs = {}
            for crate, text in sources.items():
                src = root / crate / "src"
                src.mkdir(parents=True)
                (src / "lib.rs").write_text(text, encoding="utf-8")
                dirs[crate] = root / crate
            shipped = shipped_crates(graphs(members, {}, ["shekyld"], [], pin))
            errors = headed_errors(shipped, headed, set(members))
            crates = production_crates(dirs, shipped, headed)
            sites, tested, defined, _ = scan(root, crates, {}, set())
        return errors + check(
            sites, tested, defined, {("lib/src/lib.rs", "keys"): ("G1", 1, "a KDF's output")}, {}
        )

    gui = {"package": {"name": "shekyl-gui-wallet"}, "dependencies": {}}
    shipped_only = {
        "shekyld": manifest("shekyld", {"lib": {"path": "../lib"}}),
        "lib": manifest("lib", {}),
        "outside": manifest("outside", {}),
    }
    entered = {**shipped_only, "shekyld": manifest(
        "shekyld", {"lib": {"path": "../lib"}, "outside": {"path": "../outside"}})}
    graph_cases = [
        ("a seeded site in a crate outside the graph: green", shipped_only, gui, {}, False),
        ("that crate added as a shipped binary's dependency: red", entered, gui, {}, True),
        ("that crate added as the GUI wallet's dependency: red", shipped_only,
         {**gui, "dependencies": {"outside": {}}}, {}, True),
        ("that crate listed headed for production: red", shipped_only, gui,
         {"outside": "ships later"}, True),
        ("a headed crate already in the graph: red", shipped_only, gui,
         {"lib": "ships later"}, True),
    ]
    for name, members, pin, headed, want in graph_cases:
        try:
            errors = through_the_graph(members, pin, headed)
        except GraphError as e:
            errors = [f"graph: {e}"]
        if bool(errors) != want:
            print(f"selftest FAIL: {name}: {errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")

    # A provisional marker expires when its increment lands.
    note = "PROVISIONAL until x-1: a KDF's output"
    p_row = {key: ("G1", 1, note)}
    marker = {key: ("x-1", "shekyl/x-label-v1")}
    provisional_cases = [
        ("a provisional marker before its increment lands: green", p_row, marker, set(), False),
        ("a provisional marker after its increment lands: red", p_row, marker,
         {"shekyl/x-label-v1"}, True),
        ("a marker for a site not listed: red", {}, marker, set(), True),
        ("a listing saying PROVISIONAL with no marker: red", p_row, {}, set(), True),
        ("a marker on a listing that does not say so: red", row, marker, set(), True),
    ]
    for name, listed, prov, labels, want in provisional_cases:
        errors = provisional_errors(listed, prov, labels)
        if bool(errors) != want:
            print(f"selftest FAIL: {name}: {errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")
    return failed


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    try:
        shipped = shipped_crates(live_graphs())
    except GraphError as e:
        print(f"FAIL: {e}")
        return 1
    dirs = member_dirs()
    if "--outside" in sys.argv[1:]:
        for name in sorted(set(dirs) - shipped):
            print(name)
        return 0
    errors = [
        f"{name} is in the shipped set; CF-R26 places it outside, so a manifest change "
        "pulled it into a release build"
        for name in OUTSIDE
        if name in shipped
    ]
    if INSIDE not in shipped:
        errors.append(f"{INSIDE} is not in the shipped set: the set has no subject (rule 47)")
    errors += headed_errors(shipped, HEADED_FOR_PRODUCTION, set(dirs))
    labels = registered_labels(REGISTRY.read_text(encoding="utf-8"))
    if not labels:
        errors.append("no label read from CRYPTO_DOMAIN_REGISTRY.tsv: the provisional "
                      "markers' expiry has no subject (rule 47)")
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return 1
    crates = production_crates(dirs, shipped, HEADED_FOR_PRODUCTION)
    features = test_only_features()
    sites, tested, defined, files = scan(
        RUST, crates, features, {p for p, _ in TEST_ONLY_SITES},
        {name for _, name in TEST_ONLY_SITES},
    )
    if "--list" in sys.argv[1:]:
        for (path, function), count in sorted(sites.items()):
            print(f"{path}\t{function}\t{count}")
        print(f"# {len(sites)} site(s), {sum(sites.values())} construction(s), "
              f"{files} file(s) in {len(crates)} crate(s)", file=sys.stderr)
        return 0
    if files == 0:
        print("FAIL: no Rust source read: the gate has no subject", file=sys.stderr)
        return 1
    errors = check(sites, tested, defined, SITES, TEST_ONLY_SITES)
    errors += provisional_errors(SITES, PROVISIONAL, labels)
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return 1
    print(f"PASS: {len(sites)} production site(s) building a seedable generator, each listed "
          f"with its group; {len(TEST_ONLY_SITES)} test-only site(s) held in test-only code; "
          f"{len(PROVISIONAL)} provisional listing(s) before their increment; "
          f"{files} file(s) read in {len(crates)} crate(s), shipped or headed for production "
          f"({len(dirs) - len(crates)} member(s) not shipped or without src/)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
