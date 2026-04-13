#!/usr/bin/env python3
"""
Reference implementation of Shekyl's HKDF-based output secret derivation.

Generates locked test vectors for docs/test_vectors/PQC_OUTPUT_SECRETS.json
and prints the HKDF label registry tables (markdown) to stdout.

This script is the single source of truth for the derivation spec.
Any change is a consensus change requiring explicit review.
"""

import json
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
import hmac
import hashlib

# Ed25519 scalar field order
ED25519_L = (1 << 252) + 27742317777372353535851937790883648493

# ── HKDF-SHA-512 helpers ─────────────────────────────────────────────────────

def hkdf_extract_sha512(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-512."""
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand_sha512(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand with SHA-512."""
    hash_len = 64  # SHA-512 output
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
    return okm[:length]


def wide_reduce_scalar(data_64: bytes) -> bytes:
    """
    Reduce a 64-byte value modulo the Ed25519 scalar field order l.
    Returns 32 bytes in little-endian (same as Scalar::from_bytes_mod_order_wide).
    """
    assert len(data_64) == 64
    val = int.from_bytes(data_64, "little")
    reduced = val % ED25519_L
    return reduced.to_bytes(32, "little")


def make_info(label: str, output_index: int) -> bytes:
    """Construct HKDF info string: label_bytes || output_index_le64."""
    return label.encode("utf-8") + struct.pack("<Q", output_index)


# ── Main derivation functions ─────────────────────────────────────────────────

# Instance 1: Combined shared secret derivation
SALT_COMBINED = b"shekyl-output-derive-v1"

LABEL_HO             = "shekyl-output-x"
LABEL_Y              = "shekyl-output-y"
LABEL_Z              = "shekyl-output-mask"
LABEL_K_AMOUNT       = "shekyl-output-amount-key"
LABEL_VIEW_TAG_COMB  = "shekyl-output-view-tag-combined"
LABEL_AMOUNT_TAG     = "shekyl-output-amount-tag"
LABEL_ML_DSA_SEED    = "shekyl-pqc-output"

# Instance 2: X25519-only view tag
SALT_X25519_VT = b"shekyl-view-tag-x25519-v1"
LABEL_VIEW_TAG_X25519 = "shekyl-view-tag-x25519"


def derive_output_secrets(combined_ss: bytes, output_index: int) -> dict:
    """
    Derive all output secrets from a combined shared secret.

    Returns dict with hex-encoded values for: ho, y, z, k_amount,
    view_tag_combined, amount_tag, ml_dsa_seed.
    """
    prk = hkdf_extract_sha512(SALT_COMBINED, combined_ss)

    # ho: 64-byte expand, wide-reduce to scalar
    ho_wide = hkdf_expand_sha512(prk, make_info(LABEL_HO, output_index), 64)
    ho = wide_reduce_scalar(ho_wide)

    # y: 64-byte expand, wide-reduce to scalar
    y_wide = hkdf_expand_sha512(prk, make_info(LABEL_Y, output_index), 64)
    y = wide_reduce_scalar(y_wide)

    # z: 64-byte expand, wide-reduce to scalar
    z_wide = hkdf_expand_sha512(prk, make_info(LABEL_Z, output_index), 64)
    z = wide_reduce_scalar(z_wide)

    # k_amount: 32-byte expand, raw
    k_amount = hkdf_expand_sha512(prk, make_info(LABEL_K_AMOUNT, output_index), 32)

    # view_tag_combined: 32-byte expand, first byte
    vt_comb_raw = hkdf_expand_sha512(prk, make_info(LABEL_VIEW_TAG_COMB, output_index), 32)
    view_tag_combined = vt_comb_raw[0]

    # amount_tag: 32-byte expand, first byte
    at_raw = hkdf_expand_sha512(prk, make_info(LABEL_AMOUNT_TAG, output_index), 32)
    amount_tag = at_raw[0]

    # ml_dsa_seed: 32-byte expand, raw
    ml_dsa_seed = hkdf_expand_sha512(prk, make_info(LABEL_ML_DSA_SEED, output_index), 32)

    return {
        "ho": ho.hex(),
        "y": y.hex(),
        "z": z.hex(),
        "k_amount": k_amount.hex(),
        "view_tag_combined": view_tag_combined,
        "amount_tag": amount_tag,
        "ml_dsa_seed": ml_dsa_seed.hex(),
    }


def derive_view_tag_x25519(x25519_ss: bytes, output_index: int) -> int:
    """
    Derive the X25519-only view tag (wire/scanner pre-filter).

    Uses a separate HKDF instance with its own salt.
    """
    prk = hkdf_extract_sha512(SALT_X25519_VT, x25519_ss)
    raw = hkdf_expand_sha512(prk, make_info(LABEL_VIEW_TAG_X25519, output_index), 32)
    return raw[0]


# ── Test vector generation ────────────────────────────────────────────────────

def generate_vectors() -> list:
    vectors = []

    # Group 1: All-zero combined_ss
    for idx in [0, 1]:
        css = b"\x00" * 64
        secrets = derive_output_secrets(css, idx)
        x25519_ss = b"\x00" * 32
        vt_x = derive_view_tag_x25519(x25519_ss, idx)
        vectors.append({
            "description": f"all-zero combined_ss, index={idx}",
            "combined_ss": css.hex(),
            "output_index": idx,
            **secrets,
            "x25519_ss": x25519_ss.hex(),
            "view_tag_x25519": vt_x,
        })

    # Group 2: All-0xFF combined_ss
    for idx in [0, 1]:
        css = b"\xff" * 64
        secrets = derive_output_secrets(css, idx)
        x25519_ss = b"\xff" * 32
        vt_x = derive_view_tag_x25519(x25519_ss, idx)
        vectors.append({
            "description": f"all-FF combined_ss, index={idx}",
            "combined_ss": css.hex(),
            "output_index": idx,
            **secrets,
            "x25519_ss": x25519_ss.hex(),
            "view_tag_x25519": vt_x,
        })

    # Group 3: Random combined_ss with various indices
    import hashlib as hl
    for i, idx in enumerate([0, 1, 2**32, 2**64 - 1]):
        seed = hl.sha512(f"test-vector-random-{i}".encode()).digest()
        css = seed[:64]
        x25519_ss = seed[:32]
        secrets = derive_output_secrets(css, idx)
        vt_x = derive_view_tag_x25519(x25519_ss, idx)
        vectors.append({
            "description": f"random combined_ss seed={i}, index={idx}",
            "combined_ss": css.hex(),
            "output_index": idx,
            **secrets,
            "x25519_ss": x25519_ss.hex(),
            "view_tag_x25519": vt_x,
        })

    # Group 4: Edge cases — varied combined_ss lengths and boundary indices
    for i in range(4):
        seed = hl.sha512(f"edge-case-{i}".encode()).digest()
        css = (seed + seed)[:64]
        x25519_ss = seed[:32]
        idx = [0, 255, 65535, 2**63][i]
        secrets = derive_output_secrets(css, idx)
        vt_x = derive_view_tag_x25519(x25519_ss, idx)
        vectors.append({
            "description": f"edge-case seed={i}, index={idx}",
            "combined_ss": css.hex(),
            "output_index": idx,
            **secrets,
            "x25519_ss": x25519_ss.hex(),
            "view_tag_x25519": vt_x,
        })

    # Group 5: Short combined_ss (32 bytes — X25519 only, no ML-KEM)
    for i in range(4):
        seed = hl.sha512(f"short-ss-{i}".encode()).digest()
        css = seed[:32]
        x25519_ss = seed[:32]
        idx = i
        secrets = derive_output_secrets(css, idx)
        vt_x = derive_view_tag_x25519(x25519_ss, idx)
        vectors.append({
            "description": f"short 32-byte combined_ss seed={i}, index={idx}",
            "combined_ss": css.hex(),
            "output_index": idx,
            **secrets,
            "x25519_ss": x25519_ss.hex(),
            "view_tag_x25519": vt_x,
        })

    return vectors


# ── Registry table generation ─────────────────────────────────────────────────

def print_registry_tables():
    print("## HKDF Label Registry")
    print()
    print("### Instance 1: Combined Shared Secret Derivation")
    print()
    print(f"- **Salt**: `{SALT_COMBINED.decode()}`")
    print(f"- **IKM**: `combined_ss` = X25519(eph_sk, view_pk) || ML-KEM-768.Decap(kem_sk, ct)")
    print()
    print("| Info String | Expand Size | Post-Processing | Consuming Field |")
    print("|-------------|-------------|-----------------|-----------------|")
    print(f"| `{LABEL_HO}` \\|\\| index_le64 | 64 B | `Scalar::from_bytes_mod_order_wide` | `OutputSecrets.ho` |")
    print(f"| `{LABEL_Y}` \\|\\| index_le64 | 64 B | `Scalar::from_bytes_mod_order_wide` | `OutputSecrets.y` |")
    print(f"| `{LABEL_Z}` \\|\\| index_le64 | 64 B | `Scalar::from_bytes_mod_order_wide` | `OutputSecrets.z` |")
    print(f"| `{LABEL_K_AMOUNT}` \\|\\| index_le64 | 32 B | raw | `OutputSecrets.k_amount` |")
    print(f"| `{LABEL_VIEW_TAG_COMB}` \\|\\| index_le64 | 32 B | first byte | `OutputSecrets.view_tag_combined` |")
    print(f"| `{LABEL_AMOUNT_TAG}` \\|\\| index_le64 | 32 B | first byte | `OutputSecrets.amount_tag` |")
    print(f"| `{LABEL_ML_DSA_SEED}` \\|\\| index_le64 | 32 B | raw | `OutputSecrets.ml_dsa_seed` |")
    print()
    print("### Instance 2: X25519-Only View Tag")
    print()
    print(f"- **Salt**: `{SALT_X25519_VT.decode()}`")
    print(f"- **IKM**: `x25519_ss` = X25519(eph_sk, view_pk) (first 32 bytes of combined_ss)")
    print()
    print("| Info String | Expand Size | Post-Processing | Consuming Field |")
    print("|-------------|-------------|-----------------|-----------------|")
    print(f"| `{LABEL_VIEW_TAG_X25519}` \\|\\| index_le64 | 32 B | first byte | `derive_view_tag_x25519()` return |")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    vectors = generate_vectors()

    output = {
        "description": (
            "Locked test vectors for Shekyl HKDF-based output secret derivation. "
            "Generated by tools/reference/derive_output_secrets.py. "
            "Any change to this file is a consensus change."
        ),
        "hkdf_instance_1": {
            "salt": SALT_COMBINED.decode(),
            "ikm_description": "combined_ss = X25519(eph_sk, view_pk) || ML-KEM-768.Decap(kem_sk, ct)",
        },
        "hkdf_instance_2": {
            "salt": SALT_X25519_VT.decode(),
            "ikm_description": "x25519_ss = X25519(eph_sk, view_pk)",
        },
        "vectors": vectors,
    }

    out_path = Path(__file__).parent.parent.parent / "docs" / "test_vectors" / "PQC_OUTPUT_SECRETS.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Wrote {len(vectors)} vectors to {out_path}", file=sys.stderr)
    print(file=sys.stderr)

    print_registry_tables()


if __name__ == "__main__":
    main()
