# RT-W8 — the channel's model, vectors and names: rule-26 pre-flight

**Status:** Round 0 pre-flight — **questions RULED 2026-10-09** (Rick):
`RT-O11`…`RT-O15`, §4. The substrate re-check is recorded (§2) and what
could and could not be executed is stated (§3), so the slice's commits may
proceed in the order of §5. Slice RT-W8 was authorized 2026-10-09.
**Ground:** `shekyl-core` `dev` **`a86ba6d13f`**; `clatter` **2.3.0** and
`ml-kem` **0.2.1** as published on crates.io (clatter's package records
source commit `e73cb3a060546a924779c98469bfda07d23377f6`), fetched and
read, not built. Every `file:line` below was read at one of those. Rows
F-1 to F-12 were first read against clatter's unpublished 3.0.0
(`9a8d15c4f80d5911ca0403aa22e0de99ea59df08`); RT-O12 moved the pin, and
each was read again against 2.3.0. Where the answer changed, the row says
so.
**Parent:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md) (round R1, ruled 2026-10-09)
§4.1, §4.4, §7.1, §9 and the RT-W8 row of §13. Family `RT-` (registered);
this document minted items **RT-O11…RT-O15** inside it, all now ruled.
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
| F-1 | clatter ships `hybridXK` as a named pattern in the order §4.1 adopts | clatter 2.3.0 `handshakepattern.rs:1238-1254` | **Holds.** `noise_hybrid_xk`: pre-message `s`; initiator `[skem, e, es]`, `[s, se]`; responder `[ekem, e, ee]`, `[skem]`. Identical in 3.0.0 |
| F-2 | The protocol name is `Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s` | clatter 2.3.0 `crypto_impl/x25519.rs:11-13`, `crypto_impl/rust_crypto_ml_kem.rs:28-31` | **Holds.** The code emits `25519` and `MLKEM768`. The README's example spells `X25519`; the code is what the transcript hashes |
| F-3 | Both ML-KEM libraries draw the same randomness in the same order | `ml-kem` 0.2.1 and 0.2.3 `kem.rs:128-132`, `:194-200`; `fips203` 0.4.3 `ml_kem.rs:156-162`, `:226` | **Holds; re-run against 0.2.1 as RT-O12 required, and again against 0.2.3.** Key generation `d` then `z`, 32 bytes each; encapsulation one 32-byte `m`. clatter 2.3.0 asks for `ml-kem` 0.2.1 and the lock file resolves it to **0.2.3**, which is the version built; the two read identically at these lines. The same was true of 0.3.2 |
| F-4 | Seeded randomness can be injected into clatter's hybrid handshake | clatter 2.3.0 `traits.rs:28-31`, `handshakestate/hybrid.rs:371` | **Holds, with a shape the design did not state.** The generator is a *type parameter* bounded by `RngCore + CryptoRng + Default + Clone`, and each handshake object builds its own with `RNG::default()`. A seeded stream is therefore a type whose `Default` yields it, and the two roles need two such types or they draw one stream twice |
| F-5 | Ephemeral keys can be fixed without the generator | clatter 2.3.0 `handshakestate/hybrid.rs:460-466` | **Partly.** `e` and its KEM key are generated only when not already set, so they can be preset. Encapsulation randomness always comes from the generator, so F-4's type is needed regardless |
| F-6 | One seeded stream can feed both libraries | clatter 2.3.0 `Cargo.toml` (`rand_core` `^0.6`); `rust/shekyl-p2p-transport/Cargo.toml` (`rand_core = "0.6"`) | **Moot since RT-O12.** Against 3.0.0 this was not established: it took `rand_core` 0.10 where `fips203` takes 0.6, so two adapters over one stream were needed and their agreement was itself a test. 2.3.0 takes the same `rand_core` 0.6 traits as `fips203`, so one generator type serves both and there is nothing between them to disagree |
| F-7 | Community vectors exist for the classical half | snow `tests/vectors/cacophony.txt:4913` at `8ac60f51cfe3e010c84f0a454cc575ad9204fa12`, the commit `rust/shekyl-p2p-transport/src/noise.rs:613-615` already cites | **Holds.** `Noise_XK_25519_ChaChaPoly_BLAKE2s` is present, with prologue, both statics and both ephemerals. **clatter's published package does not carry the vector files** (they are in its repository, not its crate), so the vector is taken from the file the P2P handshake already pins |
| F-8 | No published vectors exist for any hybrid pattern | clatter's repository `vectors/` (`cacophony.txt`, `snow.txt` only) | **Holds for clatter.** Its own vector files are classical; it ships none for its hybrid patterns |
| F-9 | clatter can be a dependency | `cargo search clatter` (2026-10-09) | **Yes, from the registry, at 2.3.0** (RT-O12). The unpublished 3.0.0 would have been a git dependency pinned by revision, and this workspace has none (no `git =` in any manifest) |
| F-10 | clatter's toolchain needs fit | clatter 2.3.0 `Cargo.toml` (`edition = "2021"`, `rust-version = "1.81.0"`); `rust/Cargo.toml:447` (`rust-version = "1.94"`) | **Fits.** |
| F-11 | What clatter brings into the lock file | `rust/Cargo.lock` at the commit that adds the cross-check crate | `rand_core` 0.6, `x25519-dalek` 2.0.1, `chacha20poly1305` 0.10.1 and `blake2` 0.10.6 are the versions the production graph already carries, so they add nothing. **Seven new packages, all test-only:** `clatter` 2.3.0; `ml-kem` 0.2.3; `hybrid-array` 0.2.3; `kem` 0.3.0-pre.0, the one **pre-release** among them (`ml-kem` pins it exactly); `thiserror-no-std` and `thiserror-impl-no-std` 2.0.2; and `syn` 1.0.109, a second major version of a build-time crate, pulled by the last |
| F-12 | Shekyl's Noise primitives can be called from the new work | `rust/shekyl-p2p-transport/src/aead.rs:17-93` (every item `pub(crate)`), `noise.rs:58` (`struct Sym`, private) | **They cannot.** Nothing outside that crate can reach them until RT-W9 extracts the shared core. So RT-W8 has no Shekyl handshake to compare with anything (RT-O11) |
| F-13 | Registering a domain string is a row in a file | `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` header; `scripts/ci/domain_registry_gate.sh` | **It is a row and a Rust constant.** The gate requires the literal at its defining file with a `const` definition, and pins the count of cSHAKE call sites. RT-W8 therefore lands Rust code, and needs a crate to land it in (RT-O13). *Found at commit 3:* the registry groups rows by the mechanism that hashes them, and the prologue label fits none of the six — its own bytes go into the Noise handshake hash, not through cSHAKE. It is registered under a new one-entry mechanism 7, "Noise prologue label", with the gate and the registry test taught the id. **Accepted 2026-10-09** (Rick): a label's raw bytes mixed into a handshake hash is not cSHAKE, and forcing it through cSHAKE would contradict RT-O14. One consistency point goes to RT-W9: Noise protocol names (`Noise_hybridXK_…`, and the P2P handshake's `Noise_NNhfs_…`) are also literals mixed into a handshake hash and are registered nowhere. That is defensible — they are standard pattern names, not Shekyl domain strings — but it is to be written down once, as an exclusion row with its reason, in the slice that adds the RPC protocol name |
| F-14 | The byte encodings the names depend on are fixed | `RPC_CHANNEL.md` §4.4, §5, §7.1 | **They are not.** The design names the inputs and not their encoding: how the prologue joins its customization to the network id; the input to the rendezvous name; the input to and the length of the static fingerprint (RT-O14) |
| F-15 | The model checker is available | the dev box (`proverif`, `opam`: absent); `.github/`, `scripts/` (no mention) | **Absent**, and the repository has no model-checked artifact yet, so there is no precedent for where one lives or how it is gated (RT-O15) |
| F-16 | The pinned ML-KEM crate is constant-time | `fips203` 0.4.3 `README.md:13-17`, `:64-65` | **Claimed by its authors**, at source level, with their own `dudect` measurements. RT-P4 is still ours to run: the claim is about their build and machines, and the daemon's static key meets attacker-chosen ciphertexts before anything authenticates (§4.3 there) |
| F-17 | `shekyl-rt-p2-spike` can be deleted | `rust/Cargo.toml:44`; every `Cargo.toml` under `rust/` | **Yes.** It is a workspace member with no dependents |
| F-18 | clatter's defaults are what the cross-check needs | clatter 2.3.0 `Cargo.toml` `[features]` | **They are not.** The default feature set includes `use-pqclean-ml-kem`, which brings `pqcrypto-mlkem`, a binding to the PQClean C implementation with its own C build. The cross-check declares clatter with default features off and enables only X25519, ChaCha20-Poly1305, BLAKE2 and the Rust ML-KEM backend. Left at the defaults, a test-only crate would compile C and add a second ML-KEM implementation nobody asked for |

---

## 3. Artifact execution

Rule 26 asks that the prescribed tests, benches and generators be run
before the PR opens. For this slice almost none exists yet, and this
section says exactly what was and was not done.

- **Done:** every source read in §2; clatter 2.3.0 and `ml-kem` 0.2.1
  fetched from the registry and read, not compiled (and clatter 3.0.0
  before them); the registry gate and the domain file read.
- **Not done, because the artifact does not exist:** the model, the
  vectors, the known-answer tests, the dependency gate. They are this
  slice's output.
- **Done at commit 4:** clatter 2.3.0 compiled against the workspace
  toolchain with its default features off, and its classical XK reproduced
  the community vector. F-10's reading of two manifests is now a build.
- **Not done, needs a host claim:** RT-P4 on the floor device. It is a
  long, quiet measurement and is claimed before it starts (rule 38).

---

## 4. The five questions — RULED 2026-10-09 (Rick)

### RT-O11 — What RT-W8 executes, when the handshake is RT-W9's

`RPC_CHANNEL.md` §4.1's second anchor is byte equality between clatter and
**our** handshake. F-12: RT-W8 has no handshake of ours, and may not write
one.

**RULED, as recommended: RT-W8 pins, RT-W9 compares.** RT-W8 drives
clatter's `noise_hybrid_xk` from seeded randomness with the real prologue
and commits the resulting messages and transport keys as vectors. It
checks them the only ways it can without our implementation: clatter's
classical XK reproduces the community vector (so the harness and the
vector agree), and each pinned hybrid vector is observed to change under a
named edit — a different seed, a reordered token in a local copy of the
pattern, a wrong prologue. RT-W9 implements against vectors that already
exist, red first. The second anchor is complete only when RT-W9 lands, and
RT-W8's record says so rather than claiming it.

### RT-O12 — How clatter enters the workspace

**RULED: clatter 2.3.0 from crates.io, not 3.0.0 by git**, in one
`publish = false` cross-check crate that nothing depends on, with a gate
that it is in no production graph (modelled on
`scripts/ci/check_bench_not_a_dependency.py`).

*Reason for the pin, recorded as ruled:* 2.3.0 has the same `hybridXK` and
the same handshake logic (F-1), and it shares `rand_core` 0.6,
`x25519-dalek` 2.x and `chacha20poly1305` 0.10 with the production graph
(F-11). So the workspace gains no git dependency (F-9) and no second major
version of a crate it ships. The ruling required F-3 to be re-run against
`ml-kem` 0.2.1 before any vector is generated, with a report back if the
randomness draws differed: they do not (F-3). F-6 is moot (see its row).

Two things found while re-reading against 2.3.0, both handled inside the
ruling rather than reopening it: the default features compile a C ML-KEM
(F-18), so they are turned off, and the gate holds them off; and the lock
file resolves `ml-kem` to 0.2.3, not the 0.2.1 clatter names, with one
pre-release crate in its tree (F-11). F-3 was read again at 0.2.3 before
any vector was generated.

### RT-O13 — Where the constants and the two naming functions live

**RULED, as recommended:** the channel crate is created now,
`shekyl-rpc-channel`, holding only the three constants and the two pure
functions — the rendezvous name (§7.1 there) and the static fingerprint
(§5 there) — with their known-answer tests. RT-W9 adds the handshake to
the same crate. All three constants have a use inside RT-W8 (the prologue
string goes into the pinned vectors), so none lands as a symbol waiting
for a caller (rule 23).

### RT-O14 — The exact bytes

**RULED, as recommended**, and written into `RPC_CHANNEL.md` §4.4, §5 and
§7.1:

- **Prologue:** the customization string's bytes, then the 16-byte network
  id. No separator and no length prefix.
- **Rendezvous name:** cSHAKE256 under `shekyl/rpc-rendezvous-name-v1`
  over the 16-byte network id followed by the instance name's ASCII bytes
  (`default` for the default instance); the first 12 bytes of output, as
  24 lower-case hex characters.
- **Static fingerprint:** cSHAKE256 under
  `shekyl/rpc-static-fingerprint-v1` over the X25519 public key (32 bytes)
  then the ML-KEM-768 encapsulation key (1,184 bytes); **32 bytes** of
  output. Its display format is presentation, not wire.

### RT-O15 — Where the model lives, and what runs it

**RULED, as recommended:** the model is a file in the channel crate
(`model/`), with a runner script and its expected verdicts beside it — the
property queries and the named-edit variants that must fail. A CI job
installs ProVerif, pinned by version, and runs the script; the script
fails if a property query fails **or if a named-edit variant passes**.

*Condition added with the go-ahead to install ProVerif (Rick, 2026-10-09):*
the model is run locally, not only in CI — a model that cannot be run where
it is written is not checked — and **CI runs the same ProVerif version**.
One version is pinned and installed the same way in both places (through
opam), and the runner checks the version it finds and fails on any other,
so the two cannot disagree on a verdict without saying why.

---

## 4.1 What the cross-check found by running (commits 4 to 6)

- **Message 3 is 1,264 bytes plus its payload, not 1,280.** The design
  document's cost paragraph had it wrong; the size test failed on clatter's
  output and the document is corrected. Messages 1, 2 and 4 are as stated:
  2,320, 2,320 and 1,120 plus payload.
- **F-2 holds by execution:** clatter names the protocol
  `Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s`.
- **The prologue binding is observable.** With the randomness unchanged and
  another network id, message 1 is identical except for its last 16 bytes.
- **clatter enforces PQNoise's ordering rule.** The token order this round
  first drafted (`e, es, skem`) is refused at pattern construction.
- **Still not shown, by design (RT-O11):** that Shekyl's handshake
  reproduces these vectors. That is RT-W9.

## 4.2 What the model found by running (commit 7, RT-P7)

Run 2026-10-10 with ProVerif 2.05: **27 verdicts, all as
`RPC_CHANNEL.md` §4.1 and §4.2 predict.** The table of variants, queries
and expected verdicts is `rust/shekyl-rpc-channel/model/run.py`.

- **Daemon authentication is hybrid:** it holds with X25519 broken and with
  ML-KEM broken.
- **Client authentication is classical at message 3 and hybrid at the
  first record:** with X25519 broken, ProVerif finds the attack at message
  3 and proves the property at the first record. With ML-KEM broken both
  hold.
- **The first request and the first reply stay secret** under either
  break.
- **The client's identity is hidden** from the path under either break,
  and stays hidden when the daemon's static keys leak afterwards.
- **Control:** with both primitives broken, authentication and secrecy
  fail, so the breaks have teeth.
- **Named edits fail as they must:** without message 1's `skem`, daemon
  authentication falls to a broken X25519; without `se`, client
  authentication at message 3 falls outright; without message 4's `skem`,
  client authentication at the first record falls to a broken X25519.
- **One session of each role runs to completion,** so none of this is
  about a protocol that cannot run.

Three things the running taught, kept because the next person to touch the
model will meet them:

- **A named edit exposed a flaw in the model itself.** The first version
  had the daemon accept the first record only if it carried one particular
  secret value. No attacker could produce that value whatever the handshake
  did, so the edit that removes message 4's `skem` *passed*. The daemon now
  accepts any record that opens under the session key, which is what key
  confirmation means, and the edit fails as it should. This is what the
  named edits are for.
- **Two ways of modelling a broken primitive did not terminate in
  practice.** An attacker rule for discrete logarithms beside the
  Diffie-Hellman equation, and one recovering a KEM secret key from its
  public key, reached 17 GiB in one process within half an hour. Publishing
  the secret keys instead worked for X25519 and still ran out of memory
  once the daemon's static ML-KEM key was published. The model now makes
  every shared secret of a broken primitive a public constant, which gives
  the attacker at least what a real break would, and every variant
  finishes: about 22 minutes for the slowest on the dev box.
- **RT-P7's row named a third edit, moving `skem` after `e`.** A symbolic
  model does not distinguish token order within a message, so it has no
  verdict to move. That edit is checked where it can fail: clatter refuses
  the pattern at construction (`shekyl-rpc-channel-xcheck`, §4.1).

**Installing ProVerif.** One version, 2.05, by one recipe,
`rust/shekyl-rpc-channel/model/install_proverif.sh`, run on the dev box and
by the CI job alike; `run.py` refuses any other version. The go-ahead named
opam. opam supplies the pinned OCaml toolchain, but ProVerif itself is
built from its source release with `./build -nointeract`: the opam package
depends on GTK 2 development headers for an interactive simulator the
model does not use, and those need root. Every download is checked against
a recorded SHA-256. The recipe was run from an empty directory to prove it
before it was committed.

---

## 5. Commit plan

Each is one unit of work, pushed as it is made.

| # | Commit | Notes |
|---|---|---|
| 1 | This document, with the round's ratification close-out | Docs only |
| 2 | Delete `shekyl-rt-p2-spike` | F-17; the lock diff is read and stated |
| 3 | `shekyl-rpc-channel`: the three constants, the rendezvous-name and fingerprint functions, their vectors written first and observed red, the registry rows | RT-O13, RT-O14 |
| 4–6 | **Landed as one commit** (accepted 2026-10-09), because the crate's shared test support does not compile warning-free in pieces: the cross-check crate (clatter 2.3.0, default features off) and the clatter gate with its self-test; the classical anchor against the community vector; the hybrid vectors under seeded randomness with their named edits | RT-O11, RT-O12; F-4, F-5, F-7, F-18 |
| 7 | The ProVerif model, its runner, its install recipe and its CI job — **landed 2026-10-10**, 27 verdicts as predicted (§4.2) | RT-O15; RT-P7 |
| 8 | RT-P4 on the floor device and on x86, recorded under `docs/benchmarks/` | Host claimed first |

RT-W9 is not started from this branch.
