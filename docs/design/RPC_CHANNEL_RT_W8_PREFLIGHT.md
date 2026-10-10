# RT-W8 — the channel's model, vectors and names: rule-26 pre-flight

**Status:** OPEN — Round 0 pre-flight, drafted 2026-10-09. **Not yet
discharged:** five questions (`RT-O11`…`RT-O15`, §4) are open, and no
production commit lands on this branch until they are ruled (rule 26,
*Halt*). Slice RT-W8 was authorized 2026-10-09 (Rick).
**Ground:** `shekyl-core` `dev` **`a86ba6d13f`**; `clatter` at
**`9a8d15c4f80d5911ca0403aa22e0de99ea59df08`** (v3.0.0, 2026-08-30),
fetched and read, not built. Every `file:line` below was read at one of
those two commits, and each citation says which.
**Parent:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md) (round R1, ruled 2026-10-09)
§4.1, §4.4, §7.1, §9 and the RT-W8 row of §13. Family `RT-` (registered);
this document mints open items **RT-O11…RT-O15** inside it.
**Decision authority:** Rick.

---

## 1. What RT-W8 is, and is not

RT-W8 is the evidence the handshake is built against, landed before the
handshake. From `RPC_CHANNEL.md` §13:

- the ProVerif model of `hybridXK` in its canonical token order (RT-P7),
  each query observed failing under a named edit;
- the three vector anchors of §4.1 — the community XK vectors, byte
  equality with clatter under seeded randomness, and the model;
- the registry rows `shekyl/rpc-channel-v1`,
  `shekyl/rpc-static-fingerprint-v1`, `shekyl/rpc-rendezvous-name-v1`;
- the rendezvous-name known-answer test;
- RT-P4, constant-time decapsulation;
- the gate that keeps clatter out of production dependency graphs;
- the deletion of `shekyl-rt-p2-spike` (§11.2 there).

It contains **no listener, no client, and no Shekyl implementation of the
handshake**. Those are RT-W9 and later, and none is authorized.

---

## 2. Substrate re-check

Each row is a claim the design or the slice rests on, read again at
source.

| # | Claim | Read at | Finding |
|---|---|---|---|
| F-1 | clatter ships `hybridXK` as a named pattern in the order §4.1 adopts | clatter `handshakepattern.rs:1238-1255` | **Holds.** `noise_hybrid_xk`: pre-message `s`; initiator `[skem, e, es]`, `[s, se]`; responder `[ekem, e, ee]`, `[skem]` |
| F-2 | The protocol name is `Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s` | clatter `crypto_impl/x25519.rs:12-14`, `crypto_impl/rust_crypto_ml_kem.rs:33-35` | **Holds.** The code emits `25519` and `MLKEM768`. The README's example spells `X25519`; the code is what the transcript hashes |
| F-3 | Both ML-KEM libraries draw the same randomness in the same order | `ml-kem` 0.3.2 `decapsulation_key.rs:107-114`, `encapsulation_key.rs:78-84`; `fips203` 0.4.3 `ml_kem.rs:156-162`, `:226` | **Holds, read not run.** Key generation `d` then `z`, 32 bytes each; encapsulation one 32-byte `m` |
| F-4 | Seeded randomness can be injected into clatter's hybrid handshake | clatter `traits.rs:30-36`, `handshakestate/hybrid.rs:371` | **Holds, with a shape the design did not state.** The generator is a *type parameter* bounded by `Default + Clone`, and each handshake object builds its own with `RNG::default()`. A seeded stream is therefore a type whose `Default` yields it, and the two roles need two such types or they draw one stream twice |
| F-5 | Ephemeral keys can be fixed without the generator | clatter `handshakestate/hybrid.rs:460-466` | **Partly.** `e` and its KEM key are generated only when not already set, so they can be preset. Encapsulation randomness always comes from the generator, so F-4's type is needed regardless |
| F-6 | One seeded stream can feed both libraries | clatter `Cargo.toml` (`rand_core = "0.10.1"`); `rust/shekyl-p2p-transport/Cargo.toml` (`rand_core = "0.6"`) | **Not established.** The two take different major versions of the randomness traits. Two adapters over one byte stream are needed, and that they yield the same bytes is itself something to test, not assume |
| F-7 | Community vectors exist for the classical half | clatter `vectors/cacophony.txt:4913` | **Holds.** `Noise_XK_25519_ChaChaPoly_BLAKE2s` is present, with prologue, both statics and both ephemerals |
| F-8 | No published vectors exist for any hybrid pattern | clatter `vectors/` (`cacophony.txt`, `snow.txt` only) | **Holds for clatter.** Its own vector files are classical; it ships none for its hybrid patterns |
| F-9 | clatter can be a dependency | `cargo search clatter` (2026-10-09); clatter `Cargo.toml:1-5` | **Not from the registry.** The newest published version is 2.3.0; the pinned commit is 3.0.0, unpublished. It would be a **git dependency pinned by revision**, and this workspace has none today (no `git =` in any manifest) |
| F-10 | clatter's toolchain needs fit | clatter `Cargo.toml` (`edition = "2024"`, `rust-version = "1.85.0"`); `rust/Cargo.toml:447` (`rust-version = "1.94"`) | **Fits.** |
| F-11 | What clatter brings into the lock file | clatter `Cargo.toml` `[dependencies]` | `rand_core` 0.10.1, `x25519-dalek` 3.0.0, `chacha20poly1305` 0.11.0, `ml-kem` 0.3.2, `rand` 0.10, `arrayvec`, and their trees. The first three are **second major versions** of crates the production graph already carries (0.6, 2.0.1, 0.10.1). Test-only, but it is audit surface in `Cargo.lock` |
| F-12 | Shekyl's Noise primitives can be called from the new work | `rust/shekyl-p2p-transport/src/aead.rs:17-93` (every item `pub(crate)`), `noise.rs:58` (`struct Sym`, private) | **They cannot.** Nothing outside that crate can reach them until RT-W9 extracts the shared core. So RT-W8 has no Shekyl handshake to compare with anything (RT-O11) |
| F-13 | Registering a domain string is a row in a file | `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` header; `scripts/ci/domain_registry_gate.sh` | **It is a row and a Rust constant.** The gate requires the literal at its defining file with a `const` definition, and pins the count of cSHAKE call sites. RT-W8 therefore lands Rust code, and needs a crate to land it in (RT-O13) |
| F-14 | The byte encodings the names depend on are fixed | `RPC_CHANNEL.md` §4.4, §5, §7.1 | **They are not.** The design names the inputs and not their encoding: how the prologue joins its customization to the network id; the input to the rendezvous name; the input to and the length of the static fingerprint (RT-O14) |
| F-15 | The model checker is available | the dev box (`proverif`, `opam`: absent); `.github/`, `scripts/` (no mention) | **Absent**, and the repository has no model-checked artifact yet, so there is no precedent for where one lives or how it is gated (RT-O15) |
| F-16 | The pinned ML-KEM crate is constant-time | `fips203` 0.4.3 `README.md:13-17`, `:64-65` | **Claimed by its authors**, at source level, with their own `dudect` measurements. RT-P4 is still ours to run: the claim is about their build and machines, and the daemon's static key meets attacker-chosen ciphertexts before anything authenticates (§4.3 there) |
| F-17 | `shekyl-rt-p2-spike` can be deleted | `rust/Cargo.toml:44`; every `Cargo.toml` under `rust/` | **Yes.** It is a workspace member with no dependents |

---

## 3. Artifact execution

Rule 26 asks that the prescribed tests, benches and generators be run
before the PR opens. For this slice almost none exists yet, and this
section says exactly what was and was not done.

- **Done:** every source read in §2; clatter fetched at the pinned commit
  and read, not compiled; the registry gate and the domain file read.
- **Not done, because the artifact does not exist:** the model, the
  vectors, the known-answer tests, the dependency gate. They are this
  slice's output.
- **Not done, and it could have been:** compiling clatter at the pinned
  commit against the workspace toolchain, and running its own tests. F-10
  says it should build; that is a reading of two manifests. It is the first
  thing the cross-check commit does, and a failure there is reported, not
  worked around.
- **Not done, needs a host claim:** RT-P4 on the floor device. It is a
  long, quiet measurement and is claimed before it starts (rule 38).

---

## 4. Open questions — these gate the first production commit

### RT-O11 — What does RT-W8 execute, when the handshake is RT-W9's?

`RPC_CHANNEL.md` §4.1's second anchor is byte equality between clatter and
**our** handshake. F-12: RT-W8 has no handshake of ours, and may not write
one — that is RT-W9, unauthorized.

*Recommended:* RT-W8 **pins**, and RT-W9 **compares**. RT-W8 drives
clatter's `noise_hybrid_xk` from seeded randomness with the real prologue
and commits the resulting messages and transport keys as vectors. It
checks them the only ways it can without our implementation: clatter's
classical XK reproduces the community vector (so the harness and the
vector agree), and each pinned hybrid vector is observed to change under a
named edit — a different seed, a reordered token in a local copy of the
pattern, a wrong prologue. RT-W9 then implements against vectors that
already exist, red first, which is what its row says and what rule 30
asks. The second anchor is complete only when RT-W9 lands; RT-W8's record
must say so rather than claim it.

### RT-O12 — How does clatter enter the workspace?

F-9 and F-11. The ruling asks for a test-only cross-check and a gate that
it never reaches a production graph.

- **(a) A git dependency pinned by revision, in one dedicated crate.** A
  `publish = false` cross-check crate that nothing depends on, the shape
  `shekyl-wss-q1b-bench` already has, with a gate modelled on
  `scripts/ci/check_bench_not_a_dependency.py`. Cost: the workspace's first
  git dependency, and F-11's second copies in `Cargo.lock`.
- **(b) No dependency at all.** A generator kept outside the workspace
  produces the vectors once; the vectors and the generator's source are
  committed. The lock file is untouched and "clatter is in no graph" is
  true without a gate. Cost: the cross-check does not re-run in CI, so a
  drifted vector file is caught only by re-running the generator by hand.

*Recommended:* **(a)**. The ruling asks for a check that can fail, and a
vector file nobody regenerates is a seal, not a check. The cost is real
and is disclosed in the commit that adds it, with the lock diff read.

### RT-O13 — Where do the constants and the two naming functions live?

F-13. Three domain strings need Rust constants. Two functions need a home
that both the daemon and every client can depend on: the rendezvous name
(§7.1) and the static fingerprint (§5).

*Recommended:* create the channel crate now, `shekyl-rpc-channel`, holding
only the three constants and those two pure functions with their
known-answer tests. RT-W9 adds the handshake to the same crate. All three
constants have a use inside RT-W8 — the prologue string goes into the
pinned vectors — so none lands as a symbol waiting for a caller (rule 23).

### RT-O14 — The exact bytes

F-14. Vectors freeze encodings, so these are decided before the vectors
are generated, not discovered in them.

*Recommended:*

- **Prologue:** the customization string's bytes, then the 16-byte network
  id. No separator and no length prefix: the first part is a constant and
  the second has a fixed length.
- **Rendezvous name:** cSHAKE256 under `shekyl/rpc-rendezvous-name-v1`
  over the 16-byte network id followed by the instance name's ASCII bytes
  (`default` for the default instance); the first 12 bytes of output, as
  24 lower-case hex characters. The fixed-length part comes first, so the
  input is unambiguous without a length prefix.
- **Static fingerprint:** cSHAKE256 under
  `shekyl/rpc-static-fingerprint-v1` over the X25519 public key (32 bytes)
  then the ML-KEM-768 encapsulation key (1,184 bytes) — the order the
  handshake's `s` sends them. **Output length is not ruled anywhere.**
  Recommended 32 bytes: it is an identity the daemon looks up and an
  operator pastes, never types, and a short fingerprint is a collision
  target for someone who wants one enrolment to admit another key.

### RT-O15 — Where does the model live, and what runs it?

F-15.

*Recommended:* the model is a file in the channel crate (`model/`), with a
runner script and its expected verdicts beside it — the property queries
and the named-edit variants that must fail. A CI job installs ProVerif from
the runner's package manager, pinned by version, and runs the script; the
script fails if a property query fails **or if a named-edit variant
passes**. Without CI the model is a document, and a model nobody re-runs
stops describing the code the day the pattern text moves.

---

## 5. Commit plan (after §4 is ruled)

Each is one unit of work, pushed as it is made.

| # | Commit | Notes |
|---|---|---|
| 1 | This document, with the round's ratification close-out | Docs only |
| 2 | Delete `shekyl-rt-p2-spike` | F-17; the lock diff is read and stated |
| 3 | `shekyl-rpc-channel`: the three constants, the rendezvous-name and fingerprint functions, their vectors written first and observed red, the registry rows | RT-O13, RT-O14 |
| 4 | The cross-check crate and the clatter gate, with the gate's self-test; clatter built and its own tests run | RT-O12 |
| 5 | The classical anchor: clatter's XK against the community vector | F-7 |
| 6 | The hybrid vectors under seeded randomness, each observed changing under its named edit | RT-O11; F-4, F-5, F-6 |
| 7 | The ProVerif model, its runner and its CI job | RT-O15; RT-P7 |
| 8 | RT-P4 on the floor device and on x86, recorded under `docs/benchmarks/` | Host claimed first |

RT-W9 is not started from this branch.
