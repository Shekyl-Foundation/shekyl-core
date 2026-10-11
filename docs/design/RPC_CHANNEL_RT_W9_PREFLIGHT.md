# RT-W9 — the channel itself: rule-26 pre-flight

**Status:** Round 0 pre-flight — **questions OPEN** (`RT-O16`…`RT-O22`,
§4). The substrate re-check is recorded (§2) and what could and could not
be executed is stated (§3). **No production commit is made on RT-W9 until
§4 is ruled** (rule 26's halt). Slice RT-W9 was authorized 2026-10-11
(Rick, in this lane).
**Ground:** `shekyl-core` `dev` **`258b4d8515`**, the merge of PR #1020.
Every `file:line` below was read at that commit.
**Parent:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md) (round R1, ruled 2026-10-09)
§4.1, §4.3, §4.4, §9 and the RT-W9 row of §13; the P2P round's framing
ruling, [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D14 item 4.
Family `RT-` (registered); this document mints items **RT-O16…RT-O22**
inside it.
**Decision authority:** Rick.

---

## 1. What RT-W9 is, and is not

RT-W9 builds the channel: the record layer in a crate both transports use,
Shekyl's own `hybridXK` handshake, the stream adapter that lets hyper and
axum run over records, padded records, and the handshake deadline. It also
adds one registry exclusion and turns RT-P4's standing check into a gate.

It builds **no user of the channel**. No listener, no enrolment, no
grants, no tunnel, no client posture: those are RT-W10 to RT-W12. Where a
piece of RT-W9 turns out to need one of them, the work stops and that is
reported.

Two of its numbers do not exist yet and are not chosen here: the padding
size classes, which come from RT-P5's measurement, and the handshake
deadline, which comes from RT-P6's.

---

## 2. Substrate re-check

What the slice builds on, read at source.

| # | Claim the slice rests on | Where read | Finding |
|---|---|---|---|
| F-1 | The record layer is two files that can move | `rust/shekyl-p2p-transport/src/aead.rs` (104 lines), `channel.rs` (296) | **True for the code, not for its tests.** `channel.rs` uses `aead.rs` and nothing else in the crate. Its tests do: `channel.rs:221` builds its key pairs by running the P2P handshake (`crate::noise::{Initiator, Responder}`). Moved as they are, those tests would make the record crate depend on the crate that depends on it |
| F-2 | Moving it changes only where code lives | `aead.rs:17-93`; `channel.rs:18`, `:90`; `noise.rs:29-30`; `c5_bench.rs:9-10` | **Seven items become public API of a crate.** `noise.rs` reaches `aead::{hash, hkdf, seal, open, HASH_LEN, TAG_LEN}` and `channel::halves`, all `pub(crate)` today. Across a crate boundary each must be `pub`. `REKEY_NONCES` (`channel.rs:18`) is read by `c5_bench.rs` and by tests. `Direction` can stay private. These are raw primitives: an HKDF and an AEAD seal that take a key and a nonce from the caller |
| F-3 | The P2P vectors keep passing where they are | `noise.rs:537-609` | **The test that asserts them straddles the cut.** `pinned_messages_mix_steps_and_rekey` asserts `kat_m1.hex` and `kat_m2.hex` (`:549`, `:554`), which need only `noise.rs`. The same test then asserts the key schedule and the rekey through `ck_and_k()` and `force_nonce()` (`:558-581`), which are `#[cfg(test)] pub(crate)` on the record types (`channel.rs:44-52`, `:131-140`, `:161-170`). After the move `noise.rs` cannot see another crate's `cfg(test)` items. The classical anchor has the same reach: `cacophony_nn_blake2s_matches_sym` seals with a raw transport key (`:681-682`). **This is on step 1's critical path:** that test passing unchanged is the proof that P2P's bytes did not move (RT-O16) |
| F-4 | The crate already has a pattern for exposing private entry points | `lib.rs:23-26`; `c5_bench.rs`; `Cargo.toml` (`c5-bench` feature) | **True.** A feature-gated, `#[doc(hidden)]` module of entry points that production builds leave off. The same shape would carry the test accessors of F-3 |
| F-5 | The handshake's symmetric state is shared | `noise.rs:58-131` | **It is private to the P2P handshake.** `Sym` — `mix_hash`, `mix_key`, `encrypt_and_hash`, `decrypt_and_hash` — is exactly what `hybridXK` needs and is not in either file the design names for extraction. Either it moves too, or the RPC handshake carries a second copy of a Noise symmetric state (RT-O17). The classical test vector that anchors it (`:617`) reads its fields directly |
| F-6 | Who depends on the transport crate | every `Cargo.toml` under `rust/` | Four production dependents: `shekyl-clearnet` (handshake and record types), `shekyl-transport-layer` (two flight-length constants), `shekyl-levin` and `shekyl-ffi` (the network id). `shekyl-rpc-channel` depends on it for tests only. The record types reach exactly one of them, `shekyl-clearnet` (`seam.rs:13`, `handshake.rs:18`) |
| F-7 | The fuzz targets survive the move | `rust/Cargo.toml:413-416`; `rust/shekyl-p2p-transport/fuzz/`; `.github/workflows/rust-audit-test.yml:224-226` | They name `shekyl_p2p_transport::{Initiator, Responder, RecvHalf, SendHalf}`. If the P2P crate re-exports the record types, as `lib.rs:27` does now, they need no edit. The fuzz crate is excluded from the workspace and commits no lock file, so there is no nested lock to regenerate |
| F-8 | A receive loop over records already exists | `rust/shekyl-clearnet/src/seam.rs:44-64` | **True, and it is the adapter's read half in miniature:** append bytes, open records from the front, drain what was consumed, stop on `Truncated`, fail on anything else. RT-P5's `AsyncRead` is this made asynchronous, with backpressure |
| F-9 | The record layer's own behaviour, as it stands | `channel.rs:18-22`, `:54-63`, `:146-159`, `:184-215` | Each record is two AEAD operations: an encrypted 2-byte length (`"len"` as associated data) and an encrypted body (`"body"`). Bodies are at most 65,535 bytes; a longer write is several records. Rekey is `HKDF(ck, k)` after 1,000 nonce uses per direction, with nothing on the wire to mark it. A `Truncated` read leaves the receiver usable; any other error poisons it. An empty body is rejected |
| F-10 | The pinned vectors' transport records exercise our record layer | `docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/vectors.json` (`transport`); F-9 | **They do not, and cannot.** clatter's transport message is plain Noise: one AEAD over the payload with empty associated data (40 bytes in, 56 out). Ours is the two-part record of F-9. The pinned transport bytes test **the keys `Split` produces**, by sealing with the raw key as the P2P classical test does (`noise.rs:681`); they say nothing about framing. Anchor 2 is therefore: four handshake messages, the handshake hash, and both transport keys. The record framing is tested by its own tests and is Shekyl's, as it is on P2P |
| F-11 | What the vectors pin | `vectors.json`; `rust/shekyl-rpc-channel-xcheck/tests/hybrid_xk.rs:137`, `:289-309` | Messages of 2,320, 2,320, 1,282 and 1,130 bytes with payloads of 0, 0, 18 and 10: the 1,264 and 1,120 of §4.1 plus payload. Both statics with their secret halves; the X25519 secret as 32 bytes and the ML-KEM decapsulation key in its 2,400-byte form, which `fips203` loads directly. The handshake hash. One transport ciphertext each way |
| F-12 | Our implementation can be driven from the same randomness | `vectors.json` (`rng.draw_order`); `rust/shekyl-rpc-channel-xcheck/tests/support/mod.rs`; `noise.rs:234`, `:293` | The generator is SHAKE256 over a label and a role byte, read as one stream. The draw order is written down: message 1 is the `skem` encapsulation's `m`, the X25519 ephemeral, then ML-KEM `d` and `z`. **Our handshake has to draw from the generator, not be handed seeds.** The P2P pinned tests use `keygen_from_seed` and a filler generator, so they prove nothing about draw order and are not the model for this test. The generator lives in the cross-check crate's test support; a second copy for our own test is the duplication rule 15 names (RT-O18) |
| F-13 | The P2P handshake's refusals are the ones §4.3 asks for | `noise.rs:198`, `:317` (low-order); `:264` (encapsulation key); `:504-535` (tests) | **Two of three carry over; one must not.** The low-order refusal before mixing and the FIPS 203 input check on the encapsulation key, with a test that it runs before any Diffie-Hellman, are the pattern to follow. But decapsulation failure maps to its own variant, `HandshakeError::Kem` (`:213`), distinct from a bad tag (`Decrypt`). §4.3 forbids exactly that on message 1. RT-P4 showed the error arm cannot be taken for a well-sized ciphertext, so on P2P the variant is dead; the RPC handshake does not copy it. Message 1 has one failure, of one type, with one log line |
| F-14 | The key types wipe themselves | `fips203` 0.4.3's `types.rs:6-18` and `lib.rs:95`; `noise.rs:26` | `fips203`'s key and shared-secret types derive `Zeroize` and `ZeroizeOnDrop`. `x25519-dalek`'s `StaticSecret` wipes on drop. The chaining key and transport keys are `Zeroizing` already (`noise.rs:59`, `channel.rs:34-35`). The long-term static pair is new in this slice and gets a type of its own |
| F-15 | The channel crate can hold the handshake | `rust/shekyl-rpc-channel/Cargo.toml`, `src/lib.rs` | Today it is names only: one dependency, `shekyl-crypto-hash`, and no secret anywhere. The handshake brings `fips203`, `x25519-dalek`, `zeroize`, `rand_core` and the record crate; the adapter brings `tokio` (RT-O19) |
| F-16 | The HTTP stack the adapter must sit under | `rust/shekyl-daemon-rpc/Cargo.toml:21-22`, `rust/shekyl-rpc-transport/Cargo.toml:30-36`; `rust/Cargo.lock` | Server: `axum` 0.8.8 on `tokio` 1.51. Client: `hyper` 1.9 with `hyper-util` 0.1.20. Both sides take a `tokio` `AsyncRead + AsyncWrite` |
| F-17 | P2P's framing ruling leaves room for the channel's | `P2P_TRANSPORT_LAYER.md` D14 item 4 | Fixed-window framing is ruled and unbuilt: one window is one record with **one nonce**, its plaintext opening with an authenticated 2-byte occupancy. Three things in it are explicitly not chosen: the window size, the flush policy for a partly filled window, and whether rekey becomes every-record; all wait on that round's step 7. Its sentence "the channel has its own framing" is, in context, the record channel as against Levin's `fragment.rs`, not P2P as against RPC, and does not contradict §4.4's one shared framing |
| F-18 | A record's wire length is known before it is read | F-9; F-17; §4.4 | **Not with more than one class.** Today the length travels encrypted in front of the body. P2P's single window needs no length at all. A channel with several classes needs the receiver to learn which class a record is, and the ruled design does not say how (RT-O20) |
| F-19 | Nobody else is building P2P framing | open pull requests; remote branches | **Nobody is.** No open pull request touches `shekyl-p2p-transport`. `origin/feat/p2p-cutover` is not ahead of `dev`. The one open pull request that touches RPC files is #1017 (`get_info` to Rust), which does not touch either transport crate |
| F-20 | The registry can carry an exclusion | `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv:54-58`, `:258-261`; `rust/shekyl-crypto-pq/tests/domain_registry.rs:73` | Mechanism `x`, status `excluded`, in the bottom block, each with its reason. The test pins the excluded count at 8. The registry is keyed by literal, so two protocol names are two rows and the pin goes to 10. The §13 row says "one exclusion row"; it will be two rows with one reason |
| F-21 | The standing check has fixed inputs to read | `rust/Cargo.lock` (`fips203` 0.4.3); `rust/rust-toolchain.toml` (`channel = "1.94.0"`, bump policy at `:26`); `rust/Cargo.toml:664-666`; `cmake/BuildRust.cmake:23`, `:212` | The crate version and the toolchain are each one line in one file. The release profile sets `panic` and `overflow-checks` and nothing that changes optimisation (no `opt-level`, `lto`, `codegen-units`). The C++ build bridge passes `--release` and link arguments only. That is the baseline the proposed codegen attestation would pin (RT-O22) |
| F-22 | The model that gates this slice is where the design says | `rust/shekyl-rpc-channel/model/` (`model.py`, `run.py`); `docs/formal/proverif/`; `.github/workflows/rpc-channel-model.yml:69` | The channel's model stayed in its crate; the review of #1020 moved the shared library and the install recipe to `docs/formal/proverif/` and added the P2P handshake's model beside them. The CI job is unchanged in what it runs |

---

## 3. What was and was not executed

- **Read, not run:** everything in §2. No build, test or measurement was
  made for this pre-flight.
- **Not done, because the artifact does not exist:** the handshake, the
  adapter, the padded framing, both probes, the gate. They are this
  slice's output.
- **Cannot be done from this lane alone:** RT-P5's traffic measurement
  needs a running daemon and a wallet syncing against it; RT-P6 needs the
  floor device under a quiet claim. Each is a registered measurement:
  its registration is committed and its host claimed before it runs, as
  RT-P4's were (RT-O21).

---

## 4. Open questions

Each has a recommendation. None is decided here.

### RT-O16 — How do P2P's tests reach the record layer's internals after the move?

F-3: the test that proves P2P's bytes did not move needs `ck_and_k()` and
`force_nonce()` on types that will live in another crate.

- **(a) A `test-support` feature on the record crate** exposing those
  accessors in a `#[doc(hidden)]` module, enabled only from
  dev-dependencies, with a gate that fails if any non-dev dependency
  enables it. The P2P test stays as it is, in place. This is the
  `c5-bench` pattern (F-4).
- **(b) Split the test at the crate boundary.** `noise.rs` asserts the two
  vectors and the keys it hands to `halves`; the record crate asserts the
  rekey schedule from those keys. No raw key ever leaves the record crate,
  but the test is rewritten and "passes unchanged" becomes "passes
  rewritten".

**Recommended: (a).** The requirement is that the existing test keeps
passing where it is; (a) is the only one that leaves it alone. Its cost is
a feature that exposes raw keys if someone enables it in production, which
the gate exists to stop and which the clatter gate already shows how to
check.

### RT-O17 — Does the symmetric state move with the record layer?

F-5: `Sym` is the piece both handshakes share and the design names only
`aead.rs` and `channel.rs`.

- **(a) Move it**, as the shared crate's handshake symmetric state. The
  P2P handshake keeps its tokens and its types and uses the shared state.
- **(b) Leave it and write a second one** in the RPC handshake.

**Recommended: (a).** A second symmetric state is the copy §4.4 refuses
for the record layer, in the more delicate half. It widens the extraction
by about seventy lines and one more test's reach (F-5).

### RT-O18 — Where does the seeded generator live?

F-12: the red-first test must use the generator the vectors were made
with, which today is test support inside the cross-check crate.

**Recommended:** the cross-check crate grows the comparison. Our handshake
is driven there, beside clatter, from the one generator, and both are
compared with the pinned file. The channel crate becomes a normal
dependency of a test-only crate; clatter stays out of every production
graph, and the existing gate proves it. The alternative, a small shared
test-support crate, is one more crate for sixty lines.

### RT-O19 — Which crate holds the handshake, and which the adapter?

F-15, F-16.

**Recommended:** the handshake goes in `shekyl-rpc-channel`, which then
holds secrets and is described as such. The adapter goes in its own crate,
because it brings `tokio` and the handshake has no need of an async
runtime; a daemon, a wallet and the tunnel all use both, but a test of the
handshake should not have to build a runtime. The record crate needs a
name; **proposed: `shekyl-noise-record`.**

### RT-O20 — How does a receiver learn a record's size class?

F-18. With one window there is nothing to learn. With several classes
there is, and an observer sees each record's size on the wire whatever is
done.

- **(a) Keep the encrypted length in front**, carrying the padded size.
  Two AEAD operations per record, as now; the receiver reads 18 bytes,
  learns the class, reads the rest. P2P's one-window form is then a
  different shape (one operation, no length), so "one implementation
  parameterised by a class table" has two code paths inside it.
- **(b) One operation per record, class tried in order.** The receiver
  attempts the smallest class it has bytes for. A failed attempt is an
  AEAD failure on a prefix of valid data, which the receiver must treat as
  "need more bytes", not as an attack. That weakens the rule that any
  failure but truncation poisons the half (F-9).
- **(c) One clear byte in front naming the class**, bound into the AEAD as
  associated data. One operation per record. It tells an observer nothing
  the record's length does not already tell them, and tampering with it
  fails the tag. With one class the byte is constant and P2P can omit it:
  one code path, one optional header.

**Recommended: (c).** It keeps D14's one nonce per record, keeps the
poison rule intact, and is the same code for one class and for several.
This is a wire-format decision and it is Rick's.

A second part of the same question: **rekey.** D14 leaves P2P's interval
open, to be decided with its window size. The channel's records need an
interval named. **Recommended:** keep the record layer's present rule
(F-9) for the channel in RT-W9, and let the P2P round's decision apply to
both when it is made, since the code is shared.

### RT-O21 — Where do the two measurements run?

- **RT-P5's distribution** needs real traffic: a wallet syncing, a
  submission, block batches. **Recommended:** the testnet daemon on the
  floor device with a wallet on another internal host, recorded at the
  plaintext RPC layer by a counting shim, not by packet capture. The
  method is registered before it runs.
- **RT-P6** is the floor device under a quiet claim, as RT-P4 was.

Which hosts, and whether a wallet with a long enough history exists on
the testnet to make "wallet sync" mean something, is for Rick.

### RT-O22 — Does the standing check also pin the codegen settings?

Proposed in the brief for this slice and recorded here as proposed, not
ruled. F-21 is the baseline. The argument: a change to `opt-level`, `lto`,
`codegen-units` or a target-CPU flag changes the generated code as a
toolchain bump does, and would void RT-P4's result without touching
either pinned version.

**Recommended: yes**, with the attested value being the release profile's
optimisation keys as resolved, and the gate failing on any key it does not
recognise so that a new one cannot slip past.

---

## 5. Plan

One pull request per step, each a draft off `dev`, each reviewable alone.
This document is step 0 and is the only content of the first.

| # | Step | Depends on | Notes |
|---|---|---|---|
| 0 | This pre-flight | — | Docs only |
| 1 | Extract the record layer | RT-O16, RT-O17 | A refactor. Proof: P2P's two vector files untouched and its tests passing in place; `shekyl-clearnet`'s tests passing; the fuzz targets building |
| 2 | The handshake, red first | RT-O18, RT-O19 | The comparison with the pinned vectors is written and observed failing before the implementation. Then one test per requirement of §4.3 |
| 3 | RT-P5: the adapter and the size distribution | step 2; RT-O21 | The adapter is observed failing with record splitting removed. The distribution's method is registered, and its host claimed, before it runs |
| 4 | RT-P6: handshake cost on the floor device | step 2; step 3's candidate classes | Registered before it runs; quiet claim |
| 5 | Padded records | RT-O20; steps 3 and 4 | Class table from the measurements. P2P's wire format does not change; its interim framing stays in the crate as debt owned by the P2P lane |
| 6 | Registry exclusion rows; the standing-check gate | RT-O22 | Each shown failing under a named edit |

**Named edits, fixed now so they are not improvised later.**

- *Anchor 2:* (i) draw the X25519 ephemeral before the `skem`
  encapsulation in message 1; (ii) use the first draft's token order,
  `e, es, skem`. Each must change the bytes and fail the comparison.
- *Record splitting:* remove the adapter's splitting of a write larger
  than one record; the block-batch case must fail.
- *Registry:* remove an exclusion row; the gate must reject the literal.
  Add an unregistered `shekyl/` literal; the gate must reject that too.
- *Standing check:* bump the toolchain channel on a scratch branch; the
  gate must go red and say what to run.

**What stops the slice.** The ProVerif model describes the design. If
building the handshake shows the design is wrong anywhere, the work stops
and that is reported; the code is not bent to fit, and neither is the
model. If our bytes differ from the pinned vectors, the difference is
reported and no weaker comparison is called anchor 2.

RT-W10 is not started from this slice.
