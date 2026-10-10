# Formal models — ProVerif

**Status: LIVING CONTRACT — last verified 2026-10-10 (RT-W8 part 1).**
Symbolic models of Shekyl's Noise handshakes, checked in CI against pinned
verdicts. This directory is the shared library and the P2P transport's
NNhfs model; the RPC channel's hybridXK model (RT-P7) lives with its crate
and adopts the library when it merges.

```text
docs/formal/proverif/
├── lib/noise.pvl             the shared library: symmetric state, X25519, ML-KEM, AEAD
├── nnhfs/run.py              the NNhfs model, its named edits, its pinned verdicts
├── nnhfs/nnhfs.baseline.pv   the unedited passive variant, written out for reading
├── install_proverif.sh       the one ProVerif (2.05) recipe, no root needed
└── README.md
```

## What a symbolic model says, and does not

ProVerif works in the Dolev-Yao model: every primitive is perfect unless a
rule says otherwise, and the attacker is every term it can build from what
it has seen. A verdict here is a statement about the **token order and the
transcript hashing** — which values are mixed, in which order, under which
key — not about bytes, constant time, or Shekyl's Rust.

**Out of scope, recorded as such.** Implementation correctness is the
pinned vectors (`noise.rs` tests, the Cacophony NN vector) and the
differential tests. Downgrade is decided outside Noise, by the clearnet
encryption flag (`--clearnet-transport-encrypt`); a session that never
starts this handshake is not this model's subject.

## The library — `lib/noise.pvl`

One declaration of each primitive, loaded with `proverif -lib`:

| Noise | Library | Notes |
| --- | --- | --- |
| `InitializeSymmetric(name)` | `hinit(name)` | `h = ck = HASH(name)` |
| `MixHash(data)` | `mixh(h, data)` | |
| `MixKey(ikm)` | `kdfck(ck, ikm)`, `kdfk(ck, ikm)` | HKDF's two outputs; the nonce resets per key, so a model names nonces per key |
| `MixKeyAndHash(ikm)` | `… + kdfh(ck, ikm)` | the third output, which a model mixes into `h` |
| `EncryptAndHash(m)` | `eah(k, n, h, m)` → `(ct, h')` | `aead` then `mixh` of the ciphertext |
| `Split()` | `split1(ck)`, `split2(ck)` | initiator→responder, responder→initiator |
| X25519 | `g`, `exp`, the commutation equation | low-order points do not exist here |
| ML-KEM-768 | `kpk`, `kct`, `kss`, `kdecaps` | IND-CCA: a ciphertext opens only under its secret key |
| a broken primitive | `broken_dh`, `broken_kem` | every shared secret is one public constant; see the file |

The names and signatures are the ones the RT-P7 model declared inline
(`rust/shekyl-rpc-channel/model/run.py`, #1020), so that model adopts the
library by replacing its prelude with `-lib` and nothing else (FOLLOWUPS).

## The NNhfs model — `nnhfs/run.py`

Follows `rust/shekyl-p2p-transport/src/noise.rs` exactly: both sides start
`h = ck = HASH(protocol_name)` and `MixHash(network_id)` — the prologue, the
network id being the first 16 bytes of a domain-separated cSHAKE256 of the
genesis block hash (`prefix.rs`);
message 1 is `e, ekem` hashed only (no key yet) and the empty payload
mixed; message 2 is `e`, `MixKey(ee)`, `EncryptAndHash(ekem ct)`,
`MixKey(ss)`, `EncryptAndHash(empty)`; `Split` is `HKDF(ck, empty)`.

**The attacker is passive**, by the pattern's nature: NN authenticates no
one, so an active attacker who answers message 1 is a legitimate
responder. The honest pair talk over a private link and the attacker is
handed a copy of every byte. The active attacker is run once, to record
the non-property as a verdict rather than a sentence.

| Variant | Asks | Pinned verdict |
| --- | --- | --- |
| `passive` | secrecy of both transport records and of both Split keys (`k_i2r`, `k_r2i`); honest completion reachable | secret; reachable |
| `hybrid_dh_broken` | the same with every X25519 result public | secret — ML-KEM carries it |
| `hybrid_kem_broken` | the same with every ML-KEM secret public | secret — X25519 carries it |
| `independent_of_later_ephemerals` | a completed session's records after the ephemerals of sessions started afterwards are published (phase 1) — session independence, not forward secrecy (NN has no long-term key for that term to be about) | secret |
| `network_binding` | an initiator on network A and a responder on network B completing with the same keys | unreachable |
| `active_mitm` | secrecy against an active attacker | **not secret — stated non-property: NN has no authentication, by design** |
| `both_broken` | both primitives public | not secret, as expected |
| `own_ephemerals_exposed` | a completed session's records after **its own** ephemerals are published | **not secret** — pinned so: what protects a completed session is erasure, not the pattern. `noise.rs` drops the ephemerals (`ZeroizeOnDrop`) at the end of `read_message2` / `finish`; `split` zeroes the symmetric state's `ck` but hands that value to both `Direction`s, where it persists as the rekey chain (`channel.rs` `halves`) — the chain is RT-W8 part 2's subject |

**Each property is shown failing under a named edit before its success
counts** (rule 47). The edits remove one thing the pattern carries:

| Edit | Removes | Falsifies |
| --- | --- | --- |
| `no_ekem` + X25519 broken | the KEM ciphertext | the hybrid claim's ML-KEM leg |
| `no_ee` + ML-KEM broken | the X25519 exchange | the hybrid claim's X25519 leg |
| `no_ee` + `no_ekem` | both | plain secrecy and the secrecy of both Split keys |
| `no_prologue` | the network id from `h` | network binding: cross-network completion becomes reachable |
| `reuse_eph` | fresh initiator ephemerals (one pair across sessions) | session independence under later-session compromise |

An edit whose property still holds fails the run: either the edit is not
what it says, or the property does not depend on what the design says it
does.

## Running it

```bash
docs/formal/proverif/install_proverif.sh "$HOME/.cache/shekyl-proverif"   # once; no root
export PATH="$HOME/.cache/shekyl-proverif/proverif2.05:$PATH"
python3 docs/formal/proverif/nnhfs/run.py            # every variant, ~2 s total
python3 docs/formal/proverif/nnhfs/run.py --list     # the table
python3 docs/formal/proverif/nnhfs/run.py --keep DIR # leave the generated .pv files
```

`run.py` refuses any ProVerif but 2.05 (the verdicts are pinned to it), and
refuses to run if `nnhfs.baseline.pv` is not what it would generate
(`--write-baseline` regenerates it). CI
(`.github/workflows/p2p-nnhfs-model.yml`) runs the same script on changes
to this directory, to `noise.rs`, or to the workflow, and fails if any
verdict changes.

`install_proverif.sh` is the one recipe: it builds ProVerif 2.05 from
source under a pinned OCaml from a pinned opam-repository revision, every
download checked against a recorded SHA-256. The RT-P7 model (#1020)
adopts it and the library, deleting its own copy (FOLLOWUPS).
