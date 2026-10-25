# RT-W9 — the channel itself: rule-26 pre-flight

**Status:** Round 0 pre-flight — **questions RULED 2026-10-11** (Rick):
`RT-O16`…`RT-O22`, §4, every part. **RE-RULED 2026-10-12 (PR #1034):**
`RT-O16`, `RT-O18`, `RT-O20`, and the sequencing half of `RT-O21`. The
re-rulings are what is built. An implementation opened against the
2026-10-11 text of those four is rebuilt to this document. The substrate
re-check is recorded (§2) and what could and could not be executed is
stated (§3), so the slice's steps may proceed in the order of §5.
Slice RT-W9 was authorized 2026-10-11 (Rick, in this lane). The
authorization is decision-anchored to PR #1034.
**Ground:** `shekyl-core` `dev` **`258b4d8515`**, the merge of PR #1020.
Every `file:line` below was read at that commit.
**Parent:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md) (round R1, ruled 2026-10-09)
§4.1, §4.3, §4.4, §9 and the RT-W9 row of §13; the P2P round's framing
ruling, [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D14 item 4.
Family `RT-` (registered); this document minted items **RT-O16…RT-O22**
inside it, now ruled.
**Decision authority:** Rick.

---

## 1. What RT-W9 is, and is not

RT-W9 builds the channel. `shekyl-noise` holds the handshake symmetric
state and `Direction`, the one nonce-and-rekey type both framers sit on.
The interim record framer stays in `shekyl-p2p-transport`: it has live
callers, and its wire bytes are not this slice's to change. Beside that,
the slice builds Shekyl's own `hybridXK` handshake, `ClassedRecord`, the
stream adapter `shekyl-rpc-stream`, and the handshake deadline. It also
adds two registry exclusion rows and turns RT-P4's standing check into a
gate.

It builds **no user of the channel**. No listener, no enrolment, no
grants, no tunnel, no client posture: those are RT-W10 to RT-W12. Where a
piece of RT-W9 turns out to need one of them, the work stops and that is
reported.

Two of its numbers are not chosen here: the padding size classes come
from RT-P5's measurement (RT-O6, re-ruled 2026-10-18), and the handshake
deadlines from RT-P9's (ruled 2026-10-20).

---

## 2. Substrate re-check

What the slice builds on, read at source.

| # | Claim the slice rests on | Where read | Finding |
|---|---|---|---|
| F-1 | The record layer is two files that can move | `rust/shekyl-p2p-transport/src/aead.rs` (104 lines), `channel.rs` (296) | **True for the code, not for its tests.** `channel.rs` uses `aead.rs` and nothing else in the crate. Its tests do: `channel.rs:221` builds its key pairs by running the P2P handshake (`crate::noise::{Initiator, Responder}`). Moved as they are, those tests would make the record crate depend on the crate that depends on it |
| F-2 | Moving it changes only where code lives | `aead.rs:17-93`; `channel.rs:18`, `:90`; `noise.rs:29-30`; `c5_bench.rs:9-10` | **Seven items become public API of a crate.** `noise.rs` reaches `aead::{hash, hkdf, seal, open, HASH_LEN, TAG_LEN}` and `channel::halves`, all `pub(crate)` today. Across a crate boundary each must be `pub`. `REKEY_NONCES` (`channel.rs:18`) is read by `c5_bench.rs` and by tests. `Direction` can stay private. These are raw primitives: an HKDF and an AEAD seal that take a key and a nonce from the caller. The RT-O16 re-ruling refuses that promotion: callers use `SymmetricState` and `Direction`, and the primitives stay `pub(crate)` |
| F-3 | The P2P vectors keep passing where they are | `noise.rs:537-609` | **The test that asserts them straddles the cut.** `pinned_messages_mix_steps_and_rekey` asserts `kat_m1.hex` and `kat_m2.hex` (`:549`, `:554`), which need only `noise.rs`. The same test then asserts the key schedule and the rekey through `ck_and_k()` and `force_nonce()` (`:558-581`), which are `#[cfg(test)] pub(crate)` on the record types (`channel.rs:44-52`, `:131-140`, `:161-170`). After the move `noise.rs` cannot see another crate's `cfg(test)` items. The classical anchor has the same reach: `cacophony_nn_blake2s_matches_sym` seals with a raw transport key (`:681-682`). **This is on step 1's critical path.** The re-ruling narrows the untouched proof to the vector assertions at `:549-554`; the key-schedule half moves with the types (RT-O16) |
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
| F-17 | P2P's framing ruling leaves room for the channel's | `P2P_TRANSPORT_LAYER.md` D14 item 4 | Fixed-window framing is ruled and unbuilt: one window is one record with **one nonce**, its plaintext opening with an authenticated 2-byte occupancy. Three things in it are explicitly not chosen: the window size, the flush policy for a partly filled window, and whether rekey becomes every-record; all wait on that round's step 7. Its sentence "the channel has its own framing" is, in context, the record channel as against Levin's `fragment.rs`, not P2P as against RPC. It does not contradict §4.4 as re-ruled 2026-10-12: two framers on one `Direction`, not one framer with a mode |
| F-18 | A record's wire length is known before it is read | F-9; F-17; §4.4 | **Not with more than one class.** Today the length travels encrypted in front of the body. P2P's single window needs no length at all. A channel with several classes needs the receiver to learn which class a record is, and the ruled design does not say how (RT-O20) |
| F-19 | Nobody else is building P2P framing | open pull requests; remote branches | **Nobody is.** No open pull request touches `shekyl-p2p-transport`. `origin/feat/p2p-cutover` is not ahead of `dev`. The one open pull request that touches RPC files is #1017 (`get_info` to Rust), which does not touch either transport crate |
| F-20 | The registry can carry an exclusion | `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv:54-58`, `:258-261`; `rust/shekyl-crypto-pq/tests/domain_registry.rs:73` | Mechanism `x`, status `excluded`, in the bottom block, each with its reason. The test pins the excluded count at 8. The registry is keyed by literal, so two protocol names are two rows and the pin goes to 10. At the pin the §13 row said "one exclusion row". The 2026-10-12 edit of this pre-flight makes it two rows with one reason |
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

## 4. The seven questions — RULED 2026-10-11 (Rick)

Each is kept as it was asked, with the recommendation it carried, and the
ruling under it. Where the ruling differs from the recommendation, the
ruling is what is built. The rulings were given in this lane and confirmed
there as the maintainer's own, not a draft.

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

**RULED 2026-10-11: (a) — SUPERSEDED 2026-10-12.** Rule 26 B2 rejects a
public test-only API with no production caller. The `c5-bench` feature is
a benchmark hook, not an exception, and it is not reused for keys.

**RE-RULED 2026-10-12 (PR #1034): (b), narrowed to the lines the parent
actually pins.** `RPC_CHANNEL.md` §4.4 requires `kat_m1.hex` and
`kat_m2.hex`, asserted at `noise.rs:549-554`, to stay byte-identical and
keep passing in place. Those assertions stay in `noise.rs`. Everything
below them in `pinned_messages_mix_steps_and_rekey`, and the whole of
`cacophony_nn_blake2s_matches_sym`, inspects types that are moving. Those
assertions move with `Direction` and `SymmetricState` and stay
`#[cfg(test)]` inside `shekyl-noise`. `ck_and_k` and `force_nonce` are not
exported. `hash`, `hkdf`, `seal` and `open` stay `pub(crate)`. There is
no `test-support` feature. The C5 bench may keep a feature that times one
HKDF; that feature does not return a traffic key and does not set a
nonce.

### RT-O17 — Does the symmetric state move with the record layer?

F-5: `Sym` is the piece both handshakes share and the design names only
`aead.rs` and `channel.rs`.

- **(a) Move it**, as the shared crate's handshake symmetric state. The
  P2P handshake keeps its tokens and its types and uses the shared state.
- **(b) Leave it and write a second one** in the RPC handshake.

**Recommended: (a).** A second symmetric state is the copy §4.4 refuses
for the record layer, in the more delicate half. It widens the extraction
by about seventy lines and one more test's reach (F-5).

**RULED: (a).** The shared crate is named **`shekyl-noise`**. The
symmetric state takes the protocol name as a parameter. Its type is
`SymmetricState`. **Narrowed 2026-10-12:** the crate does not hold the
interim record framer. It holds the AEAD primitives (crate-private),
`SymmetricState`, and `Direction`. A handshake ends by splitting into
two `Direction`s (`TransportKeys::into_directions`). The caller builds
its own framer around those. `Direction::seal` returns the ciphertext
and a key epoch, which advances only when rekey runs. `ClassedRecord`
stores the header-protection key against that epoch and derives it
again only when the epoch changes. The header key is not a field of
`Direction`, so the interim framer's directions do not hold a key they
never send. The label is read in one function, `header_protection_key`,
which is crate-private and born with `ClassedRecord` in step 5. The
epoch is part of `Direction` in step 1, so step 5 does not change the
signature. **UPDATE 2026-10-20:** `header_protection_key` is gone. The
label stays in `classed.rs` as `RECORD_HEADER_DST`, and the one read is
`HeaderKey::mask`, which passes those bytes to
`Direction::hkdf_from_record_key`. `Direction` no longer names the label.

### RT-O18 — Where does the seeded generator live?

F-12: the red-first test must use the generator the vectors were made
with, which today is test support inside the cross-check crate.

**Recommended:** the cross-check crate grows the comparison. Our handshake
is driven there, beside clatter, from the one generator, and both are
compared with the pinned file. The channel crate becomes a normal
dependency of a test-only crate; clatter stays out of every production
graph, and the existing gate proves it. The alternative, a small shared
test-support crate, is one more crate for sixty lines.

**RULED 2026-10-11: as recommended, under the test-support feature —
SUPERSEDED 2026-10-12.** That feature is a public test-only entry with no
production caller, which rule 26 B2 forbids. Moving clatter into
`shekyl-rpc-channel` is not the repair: the clatter gate allows exactly
one manifest to name it, the cross-check crate, and forbids any crate
from depending on that crate.

**RE-RULED 2026-10-12 (PR #1034).** The comparison lives in
`shekyl-rpc-channel`, in `mod tests` beside the handshake, so it calls a
private constructor. Production construction draws from the operating
system's source and takes no generator. The seeded generator has one
source file. The handshake's test module and the cross-check crate's
tests each compile that file; neither exports it, and neither feature
turns it on. The cross-check crate still owns clatter and still
regenerates the pinned vectors. A second copy of the generator is the
duplication this ruling refuses.

### RT-O19 — Which crate holds the handshake, and which the adapter?

F-15, F-16.

**Recommended:** the handshake goes in `shekyl-rpc-channel`, which then
holds secrets and is described as such. The adapter goes in its own crate,
because it brings `tokio` and the handshake has no need of an async
runtime; a daemon, a wallet and the tunnel all use both, but a test of the
handshake should not have to build a runtime. The record crate needs a
name; **proposed: `shekyl-noise-record`.**

**RULED: as recommended**, with the shared crate named `shekyl-noise`
(RT-O17), not the name proposed here. **Named 2026-10-12:** the adapter
crate is `shekyl-rpc-stream`. It depends on `ClassedRecord` and on
tokio. It does not depend on the handshake, and the handshake does not
depend on it.

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

**RULED: (d), a masked class byte** — none of the three above.

- At each key and each rekey, a **header-protection key** is derived from
  the record key, under a new registered label.
- The class byte is **masked** with one keystream byte computed from that
  key and the record's nonce.
- The **unmasked** byte is bound as associated data. One AEAD operation
  per record.
- The byte is **omitted for a single-class table**, so P2P's one window
  carries none. **SUPERSEDED 2026-10-12.** A table's length is not a wire
  fork. `ClassedRecord` sends the byte for every table, including a
  one-row table. `FixedWindow` is a different type: no header byte, the
  plaintext starting with the 2-byte occupancy D14 already specifies.
  RT-W9 does not build `FixedWindow`. The interim framer is neither type,
  and it is not moved in order to become one of them.
- **Rekey stays at 1,000 nonces** until the P2P round decides for both.
  The constant is `REKEY_NONCES` on `Direction`, one name.

**RE-RULED 2026-10-12 (PR #1034): the bytes are specified, in
`RPC_CHANNEL.md` §4.4.** The header-protection key, the keystream byte,
the label and its registry row, and the privacy claim all live there.
Step 5 implements that section. It does not propose the wire format
again. The 2026-10-11 claim that masking stops an observer parsing
record boundaries is superseded in the same section: the mask removes a
cleartext delimiter, and a public length set can still be segmented.

### RT-O21 — Where do the two measurements run?

- **RT-P5's distribution** needs real traffic: a wallet syncing, a
  submission, block batches. **Recommended:** the testnet daemon on the
  floor device with a wallet on another internal host, recorded at the
  plaintext RPC layer by a counting shim, not by packet capture. The
  method is registered before it runs.
- **RT-P6** is the floor device under a quiet claim, as RT-P4 was.

Which hosts, and whether a wallet with a long enough history exists on
the testnet to make "wallet sync" mean something, is for Rick.

**RULED: as recommended**, with the measurement widened and one part
left open.

- RT-P5 measures **both** the HTTP message sizes for each method **and**
  the record boundaries as the adapter emits them. **Sequencing re-ruled
  2026-10-12:** the sizes are step 3, and they are what the classes are
  derived from. The boundaries are step 5, observed from `ClassedRecord`
  under the flush policy step 3 registered. The adapter is not built on
  the interim framer in order to measure it.
- The adapter **combines writes until a flush**. That policy is part of
  the probe, registered with it and observed in it, not a detail chosen
  after.
- **Rule-21 reopen (RT-O21).** The classes are not held open waiting for
  mainnet. They ship from the registered generated trace. *Reopen when* a
  mainnet RPC trace is registered in the measurement ledger, the same
  shape as RT-P4's registration. *Re-evaluation:* a design-round entry
  that re-derives the table and names which classes moved. Rick decides.
- **Which wallet: a generated one** (ruled the same day, after the rest).
  No existing testnet wallet is used. A new wallet has no history, so the
  traffic is generated too: a regtest chain carrying full-size
  transactions, which the wallet then syncs, and a submission from it.
  What is generated, and how much, is part of step 3's registration and is
  written there before anything runs. This makes the rule-21 reopen above
  matter more, not less: the classes rest on generated traffic until
  mainnet has its own.

### RT-O22 — Does the standing check also pin the codegen settings?

Proposed in the brief for this slice and recorded here as proposed, not
ruled. F-21 is the baseline. The argument: a change to `opt-level`, `lto`,
`codegen-units` or a target-CPU flag changes the generated code as a
toolchain bump does, and would void RT-P4's result without touching
either pinned version.

**Recommended: yes**, with the attested value being the release profile's
optimisation keys as resolved, and the gate failing on any key it does not
recognise so that a new one cannot slip past.

**RULED: yes.** The gate reads `[profile.release]`,
`cmake/BuildRust.cmake` and the gitian descriptors (`contrib/gitian/`),
and fails on any key it does not recognise.

*Also ruled:* two registry rows with one reason, for the two protocol
names (F-20), is accepted. The §13 row says so.

---

## 4a. Step 5's two questions — RULED 2026-10-20 (Rick)

Step 5 split in two when it was built (the plan below). `ClassedRecord`
is specified to the byte in the parent's §4.4 and is built in step 5a.
The adapter, `shekyl-rpc-stream`, meets two points neither document
settles. They are posed here before 5b is built.

**A finding first, which closes a third point.** The fixed size of a
submission is derived from the consensus bounds (§4.4, RT-O6 part 2).
The binding bound is `TX_WEIGHT_LIMIT`, 149,400, not `MAX_TX_SIZE`
(1,000,000). A transaction's weight is its serialized size plus the Bp+
clawback, and the pool refuses any transaction whose weight exceeds the
limit. So no admissible transaction is larger than 149,400 bytes
(`shekyl-wire`'s `transaction.rs`, `TX_WEIGHT_LIMIT` and its comment). In
today's hex-in-JSON body that is 298,800 bytes plus the envelope: about
five largest-class records, not the thirty a megabyte would take. The
exact count follows from the envelope's largest size, which 5b derives
and pins by a test.

### RT-O28 — Where is a submission padded to its fixed size?

The adapter is a byte stream under HTTP. It cannot tell a submission
from any other request, and hyper writes the message and flushes once
(RT-P5's registered flush policy).

- **(a) The RPC client asks the adapter to pad the message it has just
  written.** The client that sends `submit_transaction` knows it is
  submitting. The adapter fills the message out to a fixed number of
  largest-class records. Padding records, occupancy 0, are sealed
  before the payload, so the HTTP bytes are a suffix of those records
  and the body is not complete until the last one (§4.4). A padding
  record is valid, and the daemon's adapter delivers no bytes for it.
  The HTTP body is untouched.
- **(b) Pad the HTTP body itself,** with whitespace in the JSON, or a
  padding member. That puts the rule in each client and makes the
  daemon's parser carry it. Once the body is binary (RW), the padding
  would need a field of its own.

**Recommended: (a).** It is one rule in the one adapter, enforced by
record count, and it survives the move to a binary body unchanged.

**RULED: (a), as recommended,** with a test that every
`submit_transaction` upload is exactly the fixed record count, whatever
the transaction's size.

**UPDATE 2026-10-21:** the 2026-10-20 wording of (a) put the padding
records last ("the last ones carrying occupancy 0"). That order lets
the peer answer once the body is complete, while the padding is still
unsent, and the wait publishes the submission's size. Padding is sealed
first. Occupancy 0 is only a padding record; a payload-bearing record's
occupancy is its payload. The count and option (a) are unchanged.

### RT-O29 — Which class table does the request direction use?

§4.4 rules the response classes and the submission's fixed size, and
says "requests other than a submission" are not covered.

**Recommended: the same table, 512, 16,384 and 65,535, in both
directions.** RT-P5's registration derived the classes from every record
of the trace, both directions together
(`rt_p5_rpc_message_sizes_20261017.md`, "How the classes are derived").
Every request but a submission in that trace is 431 bytes or smaller, so
it is one 512-byte record. Under RT-O28 (a), a submission is whole
65,535-byte records. One table in both directions means one
`ClassTable` constant, and a request learns nothing from its direction's
table.

**RULED: one table in both directions.** The class table stays 512,
16,384 and 65,535, as RT-O6 ruled.

## 5. Plan

One pull request per step, each a draft off `dev`, each reviewable alone.
This document is step 0 and is the only content of the first.

| # | Step | Depends on | Notes |
|---|---|---|---|
| 0 | This pre-flight | — | Docs only |
| 1 | Extract `SymmetricState` and `Direction` into `shekyl-noise`. The AEAD primitives stay crate-private | RT-O16, RT-O17 | Not a move of `channel.rs`. `SendHalf` and `RecvHalf` stay in `shekyl-p2p-transport`, call `Direction`, and keep today's wire bytes. They are live: the clearnet seam and the fuzz targets call them. Proof: `kat_m1.hex` and `kat_m2.hex` untouched; the assertions at `noise.rs:549-554` passing in place; `shekyl-clearnet`'s tests passing; the fuzz targets building. Key-schedule assertions move with `Direction` and stay `#[cfg(test)]`. No `test-support` feature. `Direction::seal` reports a key epoch from this step, so step 5 does not change its signature |
| 2 | The handshake, red first | RT-O18, RT-O19 | The comparison is an in-crate test, written and observed failing before the implementation. Production construction takes no generator. One generator source, compiled into that test and into the cross-check crate. Then one test per requirement of §4.3. Built in PR #1039 (`rust/shekyl-rpc-channel/src/pinned_handshake.rs`) |
| 3 | RT-P5 sizes | step 2; RT-O21 | HTTP message sizes per method, on the generated wallet and the generated chain. No adapter. The method, the flush policy and the host claim are registered before it runs. The classes are derived from this trace |
| 4 | RT-P6: handshake cost on the floor device | step 2; step 3's candidate classes | Registered before it runs; quiet claim |
| 4a | RT-P6's follow-through: mac1 on message 1, the handshake budget, the busy reply and the replay window | step 4 | Ruled 2026-10-20 (`RPC_CHANNEL.md` §4.3). Built in PR #1137, with RT-P6's stranger re-measured with mac1. Each check seen failing with it removed |
| 4b | RT-P9 and the handshake's deadlines; the client's retry policy | step 4a | Registered and run 2026-10-20: 4 s for message 1, 11 s for the whole handshake. One silent retry after a timeout, and a back-off after busy. Built in PR #1139 |
| 5 | `ClassedRecord` and `shekyl-rpc-stream` | RT-O20; steps 3 and 4 | The wire format is §4.4 of the parent, already specified. The adapter is written once, against `ClassedRecord`, and observed failing with splitting removed. Record boundaries are observed here, under step 3's flush policy. The header-label registry row lands with the constant. `FixedWindow` is not built. The interim framer is not copied into `shekyl-noise`. **Split 2026-10-20:** **5a** is `ClassedRecord` in `shekyl-noise`, with the registry row, a known answer and a test for each check, seen failing without it. **5b** is `shekyl-rpc-stream`, the submission's fixed size, and the record boundaries, built to RT-O28 and RT-O29 as ruled 2026-10-20 (§4a). Built 2026-10-20: the named edit (splitting removed) fails the block-batch test, and hyper flushes once per message, as RT-P5 registered |
| 6 | Two registry exclusion rows; the standing-check gate | RT-O22 | One row for each protocol-name literal, one reason, excluded-count pin 8 → 10. The registry gate gains a call-site pin for mechanism 7. The standing check reads every flag source and fails on one it does not recognise; its attestation file is seeded as attested, and RT-P4 is re-run on the Windows laptop with the shipped flags (ruled 2026-10-22, `RPC_CHANNEL.md` §10). Each gate is shown failing under a named edit. Built 2026-10-23: the rows and the pin in `scripts/ci/domain_registry_gate.sh` (32 mechanism-7 sites, and every Noise protocol-name constant an excluded row); the standing check in `scripts/ci/check_rt_p4_standing.py` over `docs/benchmarks/rt_p4_attestation.toml`, the laptop's re-run with the shipped flags failed its lines on 2026-10-25 (`docs/benchmarks/rt_p4_mlkem_decaps_timing_20261023.md`) and was ruled an observed platform property the same day, so the laptop's entry rests on the committed disassembly comparison and the check passes |
| 7 | The close-out | steps 1 to 5 | Ruled 2026-10-22, one pull request per line: the stream adapter's fixes; the noise crate's and the handshake's, with the busy back-off's jitter; these docs; step 6; then the time-bound message 1, designed and ruled before it is built (`RPC_CHANNEL.md` §10) |

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
