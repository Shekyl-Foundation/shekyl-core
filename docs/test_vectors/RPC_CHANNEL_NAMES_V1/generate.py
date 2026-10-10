#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Generator for the RPC_CHANNEL_NAMES_V1 known-answer vectors.
#
# WHY THIS IS NOT THE RUST CODE. The vectors pin three derivations in
# `shekyl-rpc-channel` (RPC_CHANNEL.md RT-O14): the Noise prologue, the
# rendezvous name, and the static fingerprint. A vector produced by the code
# it tests agrees with that code by construction and checks nothing. So this
# file carries its own cSHAKE256 -- Keccak-f[1600] and the SP 800-185
# encodings, written from the standards and sharing no line with the Rust
# implementation -- and refuses to emit anything unless that cSHAKE256
# reproduces the NIST SP 800-185 sample first.
#
# Run:    python3 generate.py            # rewrites vectors.json and manifest.json
#         python3 generate.py --check    # exit 1 if the files on disk differ
#
# The vectors change only with a deliberate, documented change to one of the
# three encodings, which is a new customization string (a `-v2`), not an edit.

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

# --- Keccak-f[1600] and cSHAKE256 (FIPS 202, SP 800-185) ---------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]
        a[0][0] ^= rc
    return a


def _keccak(rate, data, suffix, out_len):
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(suffix)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _keccak_f(state)
    out = bytearray()
    while len(out) < out_len:
        for i in range(rate // 8):
            out += state[i % 5][i // 5].to_bytes(8, "little")
        if len(out) < out_len:
            state = _keccak_f(state)
    return bytes(out[:out_len])


def _left_encode(n):
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    return bytes([len(body)]) + body


def _encode_string(s):
    return _left_encode(8 * len(s)) + s


def _bytepad(x, w):
    z = _left_encode(w) + x
    return z + b"\x00" * (-len(z) % w)


def cshake256(data, out_len, customization, function_name=b""):
    """SP 800-185 cSHAKE256. `customization` must be non-empty here: with both
    strings empty cSHAKE is defined as plain SHAKE256, which has no domain."""
    assert customization, "empty customization would be plain SHAKE256"
    rate = 136
    head = _bytepad(_encode_string(function_name) + _encode_string(customization), rate)
    return _keccak(rate, head + data, 0x04, out_len)


def _self_check():
    # The generator's own Keccak must first agree with an implementation it
    # does not share code with: Python's SHAKE256.
    for msg in (b"", b"abc", bytes(range(200))):
        assert _keccak(136, msg, 0x1F, 64) == hashlib.shake_256(msg).digest(64), \
            "Keccak core disagrees with hashlib.shake_256"
    # NIST SP 800-185 cSHAKE256 sample #3: X = 00 01 02 03, N = "",
    # S = "Email Signature", L = 512.
    want = bytes.fromhex(
        "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1"
        "64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C")
    assert cshake256(bytes([0, 1, 2, 3]), 64, b"Email Signature") == want, \
        "cSHAKE256 disagrees with the NIST SP 800-185 sample"


# --- The three derivations (RPC_CHANNEL.md RT-O14) ---------------------------

CHANNEL_DST = b"shekyl/rpc-channel-v1"
FINGERPRINT_DST = b"shekyl/rpc-static-fingerprint-v1"
RENDEZVOUS_DST = b"shekyl/rpc-rendezvous-name-v1"

NETWORK_ID_LEN = 16
X25519_PUBLIC_LEN = 32
MLKEM768_EK_LEN = 1184
RENDEZVOUS_NAME_LEN = 12
FINGERPRINT_LEN = 32


def prologue(network_id):
    assert len(network_id) == NETWORK_ID_LEN
    return CHANNEL_DST + network_id


def rendezvous_name(network_id, instance):
    assert len(network_id) == NETWORK_ID_LEN
    return cshake256(network_id + instance.encode("ascii"), RENDEZVOUS_NAME_LEN, RENDEZVOUS_DST)


def static_fingerprint(x25519_public, mlkem_ek):
    assert len(x25519_public) == X25519_PUBLIC_LEN and len(mlkem_ek) == MLKEM768_EK_LEN
    return cshake256(x25519_public + mlkem_ek, FINGERPRINT_LEN, FINGERPRINT_DST)


def _pattern(length, start, step):
    return bytes((start + step * i) % 256 for i in range(length))


def build():
    networks = [
        ("all_zero", bytes(NETWORK_ID_LEN)),
        ("counting", bytes(range(NETWORK_ID_LEN))),
        ("all_ff", b"\xff" * NETWORK_ID_LEN),
    ]
    # `default` is the default instance's own name in the derivation; the rest
    # are names an operator may give. The longest is 16 characters, the limit.
    instances = ["default", "a", "0", "bench-2", "a-b-c", "0123456789abcdef"]

    out = {
        "prologue": [
            {"id": f"prologue_{label}", "network_id_hex": nid.hex(),
             "expected": {"prologue_hex": prologue(nid).hex()}}
            for label, nid in networks
        ],
        "rendezvous_name": [
            {"id": f"name_{label}_{inst}", "network_id_hex": nid.hex(), "instance": inst,
             "expected": {"name_hex": rendezvous_name(nid, inst).hex()}}
            for label, nid in networks for inst in instances
        ],
        "static_fingerprint": [],
        # Names the instance-name rule refuses. `default` is the default
        # instance's own label and may not be given to a named one.
        "refused_instance_names": [
            "", "default", "-a", "A", "a_b", "a.b", "a/b", "..", "a b",
            "0123456789abcdefg", "café",
        ],
        "accepted_instance_names": [i for i in instances if i != "default"],
    }
    keys = [
        ("zero_keys", bytes(X25519_PUBLIC_LEN), bytes(MLKEM768_EK_LEN)),
        ("patterned", _pattern(X25519_PUBLIC_LEN, 1, 7), _pattern(MLKEM768_EK_LEN, 3, 5)),
        ("patterned_other", _pattern(X25519_PUBLIC_LEN, 200, 3), _pattern(MLKEM768_EK_LEN, 9, 11)),
    ]
    for label, x, ek in keys:
        out["static_fingerprint"].append({
            "id": f"fingerprint_{label}",
            "x25519_public_hex": x.hex(),
            "mlkem768_ek_hex": ek.hex(),
            "expected": {"fingerprint_hex": static_fingerprint(x, ek).hex()},
        })
    return out


def main():
    _self_check()
    vectors = json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    manifest = json.dumps({
        "_comment": [
            "Known-answer vectors for the three derivations of shekyl-rpc-channel",
            "(RPC_CHANNEL.md RT-O14): the Noise prologue, the rendezvous name and",
            "the static fingerprint. Produced by generate.py beside this file, which",
            "carries its own cSHAKE256 and shares no code with the Rust crate.",
            "vectors_sha256_hex covers the exact on-disk bytes of vectors.json.",
            "Regenerate only for a deliberate change of encoding, which is a new",
            "customization string, never an edit to these values.",
        ],
        "derivation_version": "v1",
        "regeneration_command": "python3 docs/test_vectors/RPC_CHANNEL_NAMES_V1/generate.py",
        "check_command": "python3 docs/test_vectors/RPC_CHANNEL_NAMES_V1/generate.py --check",
        "vectors_sha256_hex": hashlib.sha256(vectors.encode()).hexdigest(),
    }, indent=2, sort_keys=True) + "\n"

    targets = {"vectors.json": vectors, "manifest.json": manifest}
    if "--check" in sys.argv[1:]:
        stale = [n for n, want in targets.items()
                 if not (HERE / n).is_file() or (HERE / n).read_text() != want]
        if stale:
            print("RPC_CHANNEL_NAMES_V1: on-disk files differ from the generator: "
                  + ", ".join(stale), file=sys.stderr)
            return 1
        print("RPC_CHANNEL_NAMES_V1: vectors.json and manifest.json match the generator")
        return 0
    for name, text in targets.items():
        (HERE / name).write_text(text)
    print("RPC_CHANNEL_NAMES_V1: wrote vectors.json and manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
