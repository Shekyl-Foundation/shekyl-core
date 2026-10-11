# Formal models — ProVerif

**Status: LIVING CONTRACT — last verified 2026-10-10.**
Symbolic models of Shekyl's Noise handshakes, checked in CI against pinned
verdicts. This directory is the shared library and the P2P transport's
NNhfs model, which is PWD-T1's handshake. It is not the RPC slice RT-W8.
The RPC channel's hybridXK model (RT-P7) lives with its crate and adopts
the library when it merges.

```text
docs/formal/proverif/
├── lib/noise.pvl             the shared library: symmetric state, X25519, ML-KEM, AEAD
├── nnhfs/model.py            the pattern, the walk, the claims
├── nnhfs/run.py              executes variants/ and checks the pins
├── nnhfs/variants/*.pv       every variant the runner executes, generated and checked
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
starts this handshake is not this model's subject. The rekey chain that
`split` hands to both `Direction`s (`channel.rs` `halves`) is a FOLLOWUPS
row, not a query in this model.

## The library — `lib/noise.pvl`

One declaration of each primitive, loaded with `proverif -lib`. The names
and signatures are the ones the RT-P7 model declared inline, so that model
adopts the library by replacing its prelude with `-lib`.

| Noise | Library | Notes |
| --- | --- | --- |
| `InitializeSymmetric(name)` | `hinit(name)` | `h = ck = HASH(name)` |
| `MixHash(data)` | `mixh(h, data)` | |
| `MixKey(ikm)` | `kdfck(ck, ikm)`, `kdfk(ck, ikm)` | HKDF's two outputs; the nonce restarts at `n0` per key |
| `MixKeyAndHash(ikm)` | `… + kdfh(ck, ikm)` | the third output, mixed into `h` by the model that needs it |
| `EncryptAndHash(m)` | `eah(k, n, h, m)` → `(ct, h')` | `aead` then `mixh` of the ciphertext; `dah` opens |
| `Split()` | `split1(ck)`, `split2(ck)` | initiator→responder, responder→initiator |
| X25519 | `g`, `exp`, the commutation equation | low-order points do not exist here |
| ML-KEM-768 | `kpk`, `kct`, `kss`, `kdecaps` | a ciphertext opens only under its secret key |
| a broken primitive | `broken_dh`, `broken_kem` | the model uses the constant in place of that primitive's output |

`kdfh` and `n2` have no NNhfs caller. They stay for hybridXK. A break is
the constant substituted for the output, not an equation: a discrete-log
rule beside the Diffie-Hellman equation made the search grow without bound.

## The NNhfs model — `nnhfs/model.py`

The pattern is the data. `model.py` walks it once for each role. `run.py` only executes the result.

```text
-> e, ek                 hashed, then the empty payload hashed and not sent
<- e, ee, ekem, empty    MixKey(ee); EncryptAndHash(ct); MixKey(ss); EncryptAndHash(empty)
Split                    k_i2r, k_r2i
records                  length under len_ad at n0, body under body_ad at n1
```

That is `noise.rs` up to `Split`, then `channel.rs`: a 2-byte length sealed
under associated data `b"len"`, then the body under `b"body"`. The length
plaintext is the public constant `body_len`. The body plaintexts are `req`
and `rep`, and those are the secrecy queries.

An **edit** drops a token from the walk (`no_ee`, `no_ekem`), leaves the
network id out of `h` (`no_prologue`), or reuses one initiator ephemeral
pair (`reuse_eph`). A **break** uses `broken_dh` or `broken_kem` as that
step's output. The nonce is the next one under the current key, so deleting
`ekem` does not leave a hole where its seal used to be.

**The attacker is passive**, because NN authenticates no one: an active
attacker who answers message 1 is a legitimate responder. The honest pair
talk over a private link and the attacker is handed a copy of every byte.
The active attacker is one stated non-property.

Each property names the row that must flip every query it holds. A property
with no such row, a row that does not flip, or a `variants/` file that is
missing or stale, fails the run.

| Variant | Asks | Pinned verdict |
| --- | --- | --- |
| `passive` | secrecy of both record bodies and of both Split keys; honest completion reachable | secret; reachable |
| `hybrid_dh_broken` | the same, with every X25519 output the public constant | secret — ML-KEM carries it |
| `hybrid_kem_broken` | the same, with every ML-KEM secret the public constant | secret — X25519 carries it |
| `independent_of_later_ephemerals` | a finished session's bodies after ephemerals of sessions started afterwards are published. Session independence, not forward secrecy: NN has no long-term key for that term | secret |
| `network_binding` | an initiator on network A and a responder on network B finishing with the same keys | unreachable |
| `active_mitm` | secrecy against an active attacker | **not secret — NN has no authentication, by design** |
| `both_broken` | both primitives public | not secret, as expected |
| `own_ephemerals_exposed` | a finished session's bodies after **its own** ephemerals are published | **not secret** — what protects a finished session is erasure. `noise.rs` drops the ephemerals (`ZeroizeOnDrop`) at the end of `read_message2` / `finish` |

| Falsifier | Drops | Flips |
| --- | --- | --- |
| `edit_no_ee_no_ekem` | `ee` and `ekem` | plain secrecy and both Split keys |
| `edit_no_ekem_dh_broken` | `ekem`, X25519 already public | the hybrid claim's ML-KEM leg |
| `edit_no_ee_kem_broken` | `ee`, ML-KEM already public | the hybrid claim's X25519 leg |
| `edit_no_prologue` | the network id from `h` | network binding: cross-network completion becomes reachable |
| `edit_reuse_ephemeral` | fresh initiator ephemerals | session independence under later-session compromise |

## Running it

```bash
docs/formal/proverif/install_proverif.sh "$HOME/.cache/shekyl-proverif"   # once; no root; x86_64 Linux
export PATH="$HOME/.cache/shekyl-proverif/proverif2.05:$PATH"
python3 docs/formal/proverif/nnhfs/run.py            # every variant
python3 docs/formal/proverif/nnhfs/run.py --list     # each property and the row that flips it
python3 docs/formal/proverif/nnhfs/run.py --write-variants   # regenerate variants/*.pv
```

`run.py` refuses any ProVerif but 2.05, refuses a property that does not
name a row which flips it, and refuses a `variants/` directory that is not
exactly the files it would generate. Each variant runs under `prlimit`, so
the address-space cap is on the child and the runner can run variants in
parallel. CI (`.github/workflows/p2p-nnhfs-model.yml`) runs the same script
on changes to this directory, to `noise.rs`, to `channel.rs`, or to the
workflow, and fails if any verdict changes.

`install_proverif.sh` is the one recipe: ProVerif 2.05 from source, a
pinned OCaml, a pinned opam-repository revision, every download checked
against a recorded SHA-256. The RT-P7 model adopts it and the library,
deleting its own copy (FOLLOWUPS).
