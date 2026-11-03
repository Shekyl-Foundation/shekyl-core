# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for the ADDRESS_DERIVATION_V3 and ARCHIVAL_P_DERIVE_V2 vectors.

Both corpora under ``docs/test_vectors/`` are written by the Rust code they
test, so on their own they prove determinism and nothing else (rule 50: a
self-pinned vector is a tripwire, not a KAT). This script recomputes, from
each vector's inputs, every expected value that is HKDF, hash, modular or
Ed25519 base-point arithmetic, through code that shares nothing with the
Rust: HKDF-SHA-512 per RFC 5869 written over ``hmac``, Ed25519 arithmetic
per RFC 8032's reference formulas, and the derivation constants written out
below from the design (``NETWORK_IDENTITY.md`` NI-R7/NI-R10, the 2026-11-03
``V3_WALLET_DECISION_LOG.md`` entry, ``ARCHIVAL_FIREWALL_GATE6.md`` §9.3),
never parsed out of the Rust source.

One script covers both suites because they share the layer this decision
moved: ``salt_for(net)`` = ``shekyl-master-derive-v2-`` || ``shekyl/<network>``.

What it cannot recompute without an ML-KEM / ML-DSA / FN-DSA / SLH-DSA
implementation (the ML-KEM keys, the hybrid signing keys, the message-signing
key, ``p_canonical_id``) stays self-pinned; each manifest lists those under
``oracle_self_pinned``. Its primitives are anchored before use: the HKDF
against RFC 5869 test case 1, Ed25519 against RFC 8032 test 1, the
Edwards-to-Montgomery map against the base point (u = 9).

Exit status: 0 when every value matches, 1 on any mismatch, 2 when a corpus
is missing or lacks a subject this oracle exists to check (rule 47). Run
with ``python3 -I``; stdlib only.

Usage: python3 -I scripts/kat/address_derivation_v3_oracle.py [--vectors-root DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_VECTORS_ROOT = ROOT / "docs" / "test_vectors"
ADDRESS_DIR = "ADDRESS_DERIVATION_V3"
ARCHIVAL_DIR = "ARCHIVAL_P_DERIVE_V2"

# --- derivation constants, from the design text -----------------------------

NETWORKS = ("mainnet", "testnet", "stagenet", "regtest")
SALT_PREFIX = b"shekyl-master-derive-v2-"
SEED_NORMALIZE_SALT = b"shekyl-seed-normalize-v1"
SPEND_INFO = b"shekyl-ed25519-spend"
VIEW_INFO = b"shekyl-ed25519-view"
KEM_INFO = b"shekyl-ml-kem-768"
MLKEM_CHACHA_SEED_PREFIX = b"shekyl-mlkem-chacha-seed"
ADDRESS_VERSION_V1 = 0x01
CLASSICAL_ADDRESS_LEN = 1 + 32 + 32 + 48  # version, spend, view, SLH-DSA-192s pk
ML_KEM_768_EK_LEN = 1184
ML_KEM_768_DK_LEN = 2400

# Archival P: info = LABEL || 0x00 || p_slot as 4 little-endian bytes.
ARCHIVAL_INFO_SEPARATOR = b"\x00"
# kind -> (label, output length)
ARCHIVAL_LABELS = {
    "spend_wide": (b"shekyl-archival-p-ed25519-spend-v1", 64),
    "view_wide": (b"shekyl-archival-p-ed25519-view-v1", 64),
    "kem_d_z": (b"shekyl-archival-p-ml-kem-768-v1", 64),
    "account_sign_seed": (b"shekyl-archival-p-ed25519-account-sign-v1", 32),
    "ml_dsa_seed": (b"shekyl-archival-p-ml-dsa-65-v1", 32),
    "bond_spend_ed_seed": (b"shekyl-archival-p-bond-spend-ed25519-v1", 32),
    "bond_spend_ml_dsa_seed": (b"shekyl-archival-p-bond-spend-ml-dsa-65-v1", 32),
    "hs_id_seed": (b"shekyl-archival-p-hs-id-ed25519-v1", 32),
    "receipt_ed_seed": (b"shekyl-archival-p-receipt-ed25519-v1", 32),
    "receipt_fn_dsa_seed": (b"shekyl-archival-p-receipt-fn-dsa-1024-v1", 32),
}

# BIP-39 reference vectors (trezor/python-mnemonic vectors.json, English,
# 256-bit entropy): an outside implementation's spelling of these bytes.
BIP39_REFERENCE = {
    "00" * 32: " ".join(["abandon"] * 23 + ["art"]),
    "7f" * 32: "legal winner thank year wave sausage worth useful " * 2
    + "legal winner thank year wave sausage worth title",
    "80" * 32: "letter advice cage absurd amount doctor acoustic avoid " * 2
    + "letter advice cage absurd amount doctor acoustic bless",
    "ff" * 32: " ".join(["zoo"] * 23 + ["vote"]),
}

# --- HKDF (RFC 5869), by hand over hmac ---------------------------------------


def hkdf(hash_name: str, salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hash_name).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hash_name).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf512(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf("sha512", salt, ikm, info, length)


def salt_for(network: str) -> bytes:
    if network not in NETWORKS:
        raise KeyError(f"unknown network {network!r}")
    return SALT_PREFIX + b"shekyl/" + network.encode("ascii")


# --- Ed25519 (RFC 8032 section 5.1 reference arithmetic) ---------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y: int, sign: int) -> int:
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        raise ValueError("not a curve point")
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)


def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _compress(pt) -> bytes:
    zinv = pow(pt[2], P - 2, P)
    x = pt[0] * zinv % P
    y = pt[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def scalar_from_wide(wide: bytes) -> int:
    return int.from_bytes(wide, "little") % L


def scalar_bytes(s: int) -> bytes:
    return s.to_bytes(32, "little")


def scalar_base_mult(s: int) -> bytes:
    return _compress(_mul(s, BASE))


def rfc8032_public_key(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return scalar_base_mult(a)


def ed25519_to_x25519(pk: bytes) -> bytes:
    """Birational map u = (1 + y) / (1 - y) mod p (RFC 7748 section 4.1)."""
    y = int.from_bytes(pk, "little") & ((1 << 255) - 1)
    u = (1 + y) * pow((1 - y) % P, P - 2, P) % P
    return u.to_bytes(32, "little")


def self_test() -> None:
    """Anchor every primitive against a published value before trusting it."""
    okm = hkdf(
        "sha256",
        bytes(range(0x0D)),
        b"\x0b" * 22,
        bytes(range(0xF0, 0xFA)),
        42,
    )
    expect = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    if okm != expect:
        raise SystemExit("FAIL: hand-written HKDF does not reproduce RFC 5869 test case 1")
    pk = rfc8032_public_key(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    )
    if pk.hex() != "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a":
        raise SystemExit("FAIL: Ed25519 arithmetic does not reproduce RFC 8032 test 1")
    if ed25519_to_x25519(_compress(BASE)) != (9).to_bytes(32, "little"):
        raise SystemExit("FAIL: Edwards-to-Montgomery map does not send B to u = 9")


# --- checking -----------------------------------------------------------------


class Checker:
    def __init__(self) -> None:
        self.checked = 0
        self.failures: list[str] = []
        self.kinds_seen: dict[str, set[str]] = {}

    def eq(self, where: str, got: bytes, expected_hex: str) -> None:
        self.checked += 1
        got_hex, exp_hex = got.hex(), expected_hex.lower()
        if got_hex != exp_hex:
            at = next(
                (i for i, (g, e) in enumerate(zip(got_hex, exp_hex)) if g != e),
                min(len(got_hex), len(exp_hex)),
            )
            start = (at // 2) * 2
            self.failures.append(
                f"{where}: first difference at byte {at // 2} "
                f"(oracle {len(got)} bytes, vector {len(exp_hex) // 2}): "
                f"oracle ..{got_hex[start:start + 16]}.. != vector ..{exp_hex[start:start + 16]}.."
            )

    def differ(self, where: str, a: bytes, b: bytes) -> None:
        self.checked += 1
        if a == b:
            self.failures.append(f"{where}: the pair must differ and does not")

    def fact(self, where: str, ok: bool, what: str) -> None:
        self.checked += 1
        if not ok:
            self.failures.append(f"{where}: {what}")

    def saw(self, suite: str, kind: str) -> None:
        self.kinds_seen.setdefault(suite, set()).add(kind)


def load(root: pathlib.Path, name: str) -> dict:
    path = root / name / "vectors.json"
    if not path.is_file():
        print(f"FAIL: {path} is missing; nothing to check", file=sys.stderr)
        sys.exit(2)
    return json.loads(path.read_text(encoding="utf-8"))


def check_address(c: Checker, vectors: dict) -> set[str]:
    networks: set[str] = set()
    for v in vectors["tier1"]:
        kind, vid, exp = v["kind"], f"address tier1 {v['id']}", v["expected"]
        c.saw("address", kind)
        if kind == "salt_for":
            networks.add(v["network"])
            c.eq(vid, salt_for(v["network"]), exp["salt_hex"])
        elif kind == "normalize_seed":
            ikm = bytes.fromhex(v["ikm_hex"])
            c.eq(vid, hkdf512(SEED_NORMALIZE_SALT, ikm, b"", 64), exp["master_seed_hex"])
        elif kind in ("derive_spend_wide", "derive_view_wide", "derive_kem_d_z"):
            info = {
                "derive_spend_wide": SPEND_INFO,
                "derive_view_wide": VIEW_INFO,
                "derive_kem_d_z": KEM_INFO,
            }[kind]
            networks.add(v["network"])
            master = bytes.fromhex(v["master_seed_hex"])
            wide = hkdf512(salt_for(v["network"]), master, info, 64)
            c.eq(vid + " wide", wide, exp["wide_hex"])
            if kind == "derive_kem_d_z":
                c.fact(vid, "scalar_hex" not in exp, "d_z carries no scalar")
            else:
                c.eq(vid + " scalar", scalar_bytes(scalar_from_wide(wide)), exp["scalar_hex"])
        elif kind == "ml_kem_chacha_seed":
            d_z = bytes.fromhex(v["d_z_hex"])
            got = hashlib.sha3_256(MLKEM_CHACHA_SEED_PREFIX + d_z).digest()
            c.eq(vid, got, exp["chacha_seed_hex"])
        elif kind == "network_separation":
            master = bytes.fromhex(v["master_seed_hex"])
            sks = []
            for side in ("a", "b"):
                net = v[f"network_{side}"]
                networks.add(net)
                wide = hkdf512(salt_for(net), master, SPEND_INFO, 64)
                sk = scalar_bytes(scalar_from_wide(wide))
                c.eq(f"{vid} spend_sk_{side}", sk, exp[f"spend_sk_{side}_hex"])
                sks.append(sk)
            c.differ(vid, sks[0], sks[1])
        else:
            c.fact(vid, False, f"unknown kind {kind!r}; the oracle must be taught it")

    for v in vectors["tier2"]:
        vid, exp, net = f"address tier2 {v['id']}", v["expected"], v["network"]
        c.saw("address", "tier2")
        networks.add(net)
        seed = bytes.fromhex(v["seed_hex"])
        c.fact(vid, len(seed) == 32, "seed is not 32 bytes")
        master = hkdf512(SEED_NORMALIZE_SALT, seed, b"", 64)
        c.eq(vid + " master_seed", master, exp["master_seed_hex"])
        salt = salt_for(net)
        spend = scalar_from_wide(hkdf512(salt, master, SPEND_INFO, 64))
        view = scalar_from_wide(hkdf512(salt, master, VIEW_INFO, 64))
        c.eq(vid + " spend_sk", scalar_bytes(spend), exp["spend_sk_hex"])
        c.eq(vid + " view_sk", scalar_bytes(view), exp["view_sk_hex"])
        spend_pk = scalar_base_mult(spend)
        view_pk = scalar_base_mult(view)
        c.eq(vid + " spend_pk", spend_pk, exp["spend_pk_hex"])
        c.eq(vid + " view_pk", view_pk, exp["view_pk_hex"])
        x25519 = ed25519_to_x25519(view_pk)
        c.eq(vid + " x25519_pk", x25519, exp["x25519_pk_hex"])

        # Composition: the oracle cannot run ML-KEM or SLH-DSA keygen, but it
        # can check the composite fields are built from the parts it derived.
        pqc = bytes.fromhex(exp["pqc_public_key_hex"])
        ek = bytes.fromhex(exp["ml_kem_ek_hex"])
        c.eq(vid + " pqc_public_key[..32]", pqc[:32], x25519.hex())
        c.fact(vid, pqc[32:] == ek and len(ek) == ML_KEM_768_EK_LEN, "pqc_public_key != x25519 || ml_kem_ek")
        c.fact(vid, len(bytes.fromhex(exp["ml_kem_dk_hex"])) == ML_KEM_768_DK_LEN, "ml_kem_dk length")
        classical = bytes.fromhex(exp["classical_address_bytes_hex"])
        c.fact(vid, len(classical) == CLASSICAL_ADDRESS_LEN, "classical address length")
        c.eq(
            vid + " classical[..65]",
            classical[:65],
            (bytes([ADDRESS_VERSION_V1]) + spend_pk + view_pk).hex(),
        )

        words = v.get("mnemonic_words")
        if words is not None:
            c.saw("address", "tier2_words")
            reference = BIP39_REFERENCE.get(v["seed_hex"].lower())
            c.fact(
                vid,
                reference is not None,
                "mnemonic_words on a seed with no BIP-39 reference vector; the oracle cannot vouch for it",
            )
            if reference is not None:
                c.fact(vid, words == reference, "mnemonic_words != BIP-39 reference spelling of seed_hex")
    return networks


def archival_out(kind: str, master: bytes, net: str, slot: int) -> bytes:
    label, length = ARCHIVAL_LABELS[kind]
    info = label + ARCHIVAL_INFO_SEPARATOR + slot.to_bytes(4, "little")
    return hkdf512(salt_for(net), master, info, length)


# pair kind -> (kind of side a, kind of side b, does side b take network_b)
ARCHIVAL_PAIRS = {
    "hs_id_network_separation": ("hs_id_seed", "hs_id_seed", True),
    "receipt_network_separation": ("receipt_fn_dsa_seed", "receipt_fn_dsa_seed", True),
    "hs_id_label_separation": ("hs_id_seed", "account_sign_seed", False),
    "receipt_label_separation": ("receipt_ed_seed", "account_sign_seed", False),
    "label_separation": ("account_sign_seed", "bond_spend_ed_seed", False),
}


def check_archival(c: Checker, vectors: dict) -> set[str]:
    networks: set[str] = set()
    for v in vectors["tier1"]:
        kind, vid, exp = v["kind"], f"archival tier1 {v['id']}", v["expected"]
        c.saw("archival", kind)
        master = bytes.fromhex(v["master_seed_hex"])
        net, slot = v["network"], v["p_slot"]
        networks.add(net)
        if kind in ARCHIVAL_LABELS:
            c.eq(vid, archival_out(kind, master, net, slot), exp["out_hex"])
        elif kind == "hs_id_pubkey":
            seed = archival_out("hs_id_seed", master, net, slot)
            c.eq(vid, rfc8032_public_key(seed), exp["out_hex"])
        elif kind in ARCHIVAL_PAIRS:
            kind_a, kind_b, cross_net = ARCHIVAL_PAIRS[kind]
            net_b = v["network_b"] if cross_net else net
            networks.add(net_b)
            a = archival_out(kind_a, master, net, slot)
            b = archival_out(kind_b, master, net_b, slot)
            c.eq(vid + " a", a, exp["out_a_hex"])
            c.eq(vid + " b", b, exp["out_b_hex"])
            c.differ(vid, a, b)
        elif kind == "slot_separation":
            # Hybrid Ed25519 + ML-DSA-65 public keys: self-pinned. The oracle
            # checks only that the pinned pair differs.
            c.differ(vid, bytes.fromhex(exp["out_a_hex"]), bytes.fromhex(exp["out_b_hex"]))
        else:
            c.fact(vid, False, f"unknown kind {kind!r}; the oracle must be taught it")

    for v in vectors["tier2"]:
        vid, exp = f"archival tier2 {v['id']}", v["expected"]
        c.saw("archival", "tier2")
        master = bytes.fromhex(v["master_seed_hex"])
        net, slot = v["network"], v["p_slot"]
        networks.add(net)
        spend = scalar_from_wide(archival_out("spend_wide", master, net, slot))
        view = scalar_from_wide(archival_out("view_wide", master, net, slot))
        c.eq(vid + " spend_sk", scalar_bytes(spend), exp["spend_sk_hex"])
        c.eq(vid + " view_sk", scalar_bytes(view), exp["view_sk_hex"])
        spend_pk = scalar_base_mult(spend)
        view_pk = scalar_base_mult(view)
        c.eq(vid + " spend_pk", spend_pk, exp["spend_pk_hex"])
        c.eq(vid + " view_pk", view_pk, exp["view_pk_hex"])
        c.eq(vid + " x25519_pk", ed25519_to_x25519(view_pk), exp["x25519_pk_hex"])
    return networks


# Subjects each suite must carry, or this oracle is checking nothing (rule 47).
REQUIRED_KINDS = {
    "address": {
        "salt_for",
        "normalize_seed",
        "derive_spend_wide",
        "derive_view_wide",
        "derive_kem_d_z",
        "ml_kem_chacha_seed",
        "network_separation",
        "tier2",
        "tier2_words",
    },
    "archival": set(ARCHIVAL_LABELS) | set(ARCHIVAL_PAIRS) | {"hs_id_pubkey", "tier2"},
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--vectors-root",
        type=pathlib.Path,
        default=DEFAULT_VECTORS_ROOT,
        help=f"directory holding {ADDRESS_DIR}/ and {ARCHIVAL_DIR}/",
    )
    args = parser.parse_args()

    self_test()
    c = Checker()
    covered = {
        "address": check_address(c, load(args.vectors_root, ADDRESS_DIR)),
        "archival": check_archival(c, load(args.vectors_root, ARCHIVAL_DIR)),
    }

    missing = []
    for suite, kinds in REQUIRED_KINDS.items():
        absent = kinds - c.kinds_seen.get(suite, set())
        if absent:
            missing.append(f"{suite}: no vectors of kind {sorted(absent)}")
        nets = set(NETWORKS) - covered[suite]
        if nets:
            missing.append(f"{suite}: no vectors on {sorted(nets)}")

    for failure in c.failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    for gap in missing:
        print(f"FAIL: {gap}", file=sys.stderr)
    if c.failures:
        print(f"{len(c.failures)} of {c.checked} values disagree with the oracle", file=sys.stderr)
        return 1
    if missing:
        return 2
    print(
        f"OK: {c.checked} values in {ADDRESS_DIR} and {ARCHIVAL_DIR} recomputed "
        f"independently; all agree"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
