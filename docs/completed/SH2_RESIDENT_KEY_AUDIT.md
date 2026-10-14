# SH-2 resident attestation key — Round 0 pre-flight audit

**Status:** CLOSED-as-record (2026-10-14, archived by ruling on PR #1076).
Round 0 (pre-flight) recorded 2026-10-06; implementation landed in the same
PR (#990). §9.7 item 3 RULED 2026-10-07 (§4). It owns no open work: the
receipt key's selection on the serving path, named in §6, is owned by
[`FN_DSA_HYBRID.md`](../design/FN_DSA_HYBRID.md) §9.4. Do not implement from
this record.
**Substrate verified at:** `origin/dev` = `0e1d1d6126` (PR #982 merged).
**Branch / worktree:** `feat/sh2-resident-pass-key`.
**Anchors:** `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.7 (the SH- composition
slice; item 3's SH-2 closure criterion); `ARCHIVAL_SHARD_FETCH.md` `SF-D13`
("injection, not custody"; "named residency"); `BENCHMARK_ALIGNMENT.md` §S
(the open question this slice answers); `FOLLOWUPS.md` *Daemon shard-fetch
client (`SF-` round)* → SH-2 bullet (the TJ-D counters surface rides here);
`IMPLEMENTATION_INDEX.md` `SH-1…SH-3`.

This is the rule-26 Round 0 record for the SH-2 remainder: wiring the
persona's resident `hybrid_sign_sk` as the `PassKey` that `engine-core`
binds, in place of `NoResidentKey`. It is not a redesign. Every ruling
below was put to the maintainer on 2026-10-06 and is recorded with its
answer; the substrate table is what those rulings were made against.

## 1. No C++ is touched, and why that is structural

`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.7 item 1 recorded for SH-1 that "the
composition is entirely Rust, and nothing crosses the FFI". That holds for
SH-2 by the shape of the path, not by restraint: the secret lives in the
kameo `StakeEngine` actor (`ArchivalPKeys.hybrid_sign_sk`,
`rust/shekyl-crypto-pq/src/archival_p.rs`); the seam is
`shekyl_p_serve::PassKey`; the construction site is
`rust/shekyl-engine-core/src/engine/stake_engine/serving/start.rs` (the
`key:` field of `PersonaServing`); the only consumer of the resulting
signature is `shekyl_archival_retention::verify_pass_transcript`, called by
`shekyl-p-fetch` in the daemon's Rust fetch client. The C++ serve-credit
verifier is `DEL-008` and this path never reaches it.

## 2. Substrate re-check

| Disposition cites | Found at the pin | Verdict |
|---|---|---|
| `SF-D13`: countersign with the bond record's hybrid identity key | `ArchivalPKeys.hybrid_sign_pk == hybrid_bond_id`; `hybrid_sign_sk` already signs `SCHEME_DOMAIN_PQC_AUTH_TX` (`stake_engine/bond.rs`) and `SCHEME_DOMAIN_EMISSION_CLAIM` (`stake_engine/claim.rs`) | Holds. **One key, three domains** — the fact that decides ruling Q1 |
| The signer seam | `PassKey { ready(shard_id, anchor_height), sign_pass(message) }`, `PassSigner::own_height`, `sign_pass_transcript` as the only signing call (`shekyl-p-serve/src/countersign.rs`) | Holds. #982 replaced `can_sign() -> bool` with `ready(..) -> Result<(), SignRefused>`; this record is against the new shape |
| Both key calls run on the blocking pool | `serve.rs`: `ready` before the head and `sign_pass` after the body, each inside `spawn_blocking` | Holds. A blocking actor round-trip from there is legitimate (`tokio::sync::oneshot::Receiver::blocking_recv` panics only on an executor thread) |
| §7.2(iii) custody precedent | `PersonaOnionIdentityOf` expands `hs_id_seed` **in-actor** and returns only the credential (`stake_engine/persona.rs`) | The precedent is in-actor expansion, never secret export |
| Actor message discipline | `ScanStep` holds `&mut self` across its `spawn_blocking`, so the mailbox queues behind one bounded step (`stake_engine/scan.rs`); `on_stop` wipes `held` (`stake_engine/actor.rs`) | A sign message queues behind an in-flight scan step — bounded by the client's `body_stall` (below) |
| Mid-session re-activation | `StakeEngineHandle::activate_persona` is `#[allow(dead_code)]`, every caller `cfg(test)` (`stake_engine/handle.rs`) | The key binds to `active.p_slot` at start; there is no production re-key path to design for |
| Actor liveness is cheap | `ActorRef::is_alive()` is `!mailbox_sender.is_closed()`; `WeakActorRef::upgrade()` exists (kameo `=0.20.0`) | The resident key can hold a **weak** ref: it cannot extend the secret's life past signs already in flight (each sign upgrades for one blocking `ask`; #990 review F2 sharpened the wording), and `ready` is one atomic read |
| Blocking ask exists | `AskRequest::blocking_send` (kameo `src/request/ask.rs`) | No runtime handle needs capturing |
| Close order | `take_and_close_tenant`: `tasks.shutdown().await` (cadence → serving, awaited) **before** `drop(engine)` (`shekyl-wallet-rpc/src/lifecycle.rs`) | Serving stops first; the actor's last strong ref goes with the engine. Serving life ⊂ key life in the production close order, and the weak ref makes it so by construction everywhere else |
| Client's wait for the trailer | `shekyl-p-fetch` `Timeouts::DEFAULT.body_stall = 30 s` | The sign must return within 30 s of the last body byte; one ML-DSA-65 + Ed25519 sign plus one scan-step wait fits by orders of magnitude |
| §9.7 item 3 (sealed `ServeSet`) | `ServeSet::reported` / `reported_prefix` are `pub(crate)`; `from_connected_record` is gone; **but** `ReportedSet` (`serve_set/report.rs`) is a public enum any `ServeSetPinner` impl may construct, and `serving/task.rs` tests build it as a literal | **Not discharged; the hazard moved one type outward.** See §4 |
| SH-2a / SH-2b-2 | §9.7 item 5 CLOSED 2026-08-15 | Done |
| TJ-D counters surface | `rg 'counters\(\)' rust/shekyl-engine-core/src` → no non-test read; the alarm board (`shekyl-operator-alarm`) has no serve-health condition | Owed here by the FOLLOWUPS ruling ("lands no later than SH-2"); ruling Q3 |
| `check_p_fetch_dep_cut.py` | Dev-dependencies are not followed; `shekyl-p-serve` already dev-depends on `shekyl-p-fetch` | An `engine-core` dev-dep on `shekyl-p-fetch` for the proving test is inside the gate's own premise |

## 3. Rulings (maintainer, 2026-10-06)

**Q1 — where the signature is produced: (a) in-actor.** A new message
`SignPassTranscript { p_slot, message }` is handled inside `StakeEngine`;
the serving role holds a weak actor ref plus the slot and asks for a
signature per served shard. The secret never leaves the actor. Alternative
(b), exporting a domain-restricted signer object holding a copy of
`hybrid_sign_sk`, was rejected: unlike `hs_id_seed`'s onion expansion, this
key authorises three domains cryptographically, so the restriction would be
API-level — one edit from signing an emission claim from the serving task,
against the `EU` §1 host-compromise model.

**Q2 — `ready` semantics: actor liveness.** `ready` is `Ok` iff the weak
ref upgrades and the actor is alive; otherwise `SignRefused`. This answers
`BENCHMARK_ALIGNMENT.md` §S's open question ("can the signing capability go
away while the listener stays up?"): it can, in exactly one way — the actor
fail-stopped (handler panic) — and that case is now the shared pre-flight
503, not a distinguishable truncated 200. The refusal trailer is reserved
for a cryptographic fault at sign time. The close order above is pinned by
test, not assumed.

**Q3 — TJ-D counters surface: included in this PR.** `ServeCounters` become
an alarm-board input: a `serve_health` producer in `shekyl-operator-alarm`
(one pure `apply` over one observation, the shape `serve_set` and
`tor_posture` set), a `ServeHealth` condition, and the serving task feeding
it each cadence with the tick's *movement* (`ServeCounters::since`, the
one home of the subtraction) rather than the session totals, so a quiet tick
clears the row. *Amended at review (2026-10-07):* the reading was first
taken in the refresh loop after `observe().await`; that await is the host's
`refresh`, which waits on the store actor with no timeout, so a key that
began refusing while a refresh was wedged would have reached the board only
when the refresh did. The reading now runs on its own probe task
(`serving::health`, the shape the disk probe already had) through the
host's detached `ServeCounterReader`, and teardown drains the probe before
disarming the row. The same review put the refresh itself under the task's
cancel `select!`: a refresh wedged on the actor had held
`ServingHandle::shutdown` open, and now shutdown drops the attempt (the
previous pins stay, the swap never ran) and proceeds to teardown — pinned by
`shutdown_completes_while_a_refresh_is_wedged_on_the_actor`. No wallet-RPC
wire change: the row names the alarm board,
and the board is an embedder surface, not a method. *Amended at build
(2026-10-06):* the pre-flight text also named a `ServingHandle::counters()`
snapshot accessor; it is not built — no production consumer reads it, and
an accessor with no reader is the bare-symbol grep hit rule 23 forbids. The
board row is the operator surface; a raw-counter accessor reopens if an
embedder names a reading the row does not carry.

**Q4 — the proving test lives in `engine-core`'s serving tests.** The
persona key sits behind a real `PServeEndpoint`, fetched by `PFetchClient`
through one loopback SOCKS shim, `shekyl-p-loopback`, and verified by
`verify_pass_transcript` against the persona's `bond_id`. The signer is
`HostSigner` (`signer_at_synced_tip` stamps the daemon tip once). `SF-D4`
keeps that edge out of both shipped graphs: the crate is a dev-dependency,
and the wallet names neither `shekyl-p-fetch` nor `shekyl-p-serve`. The
`shekyl-sp-t3-spike` rig was the alternative and was not chosen.

**Taken without a question, disclosed here:** the key binds to
`active.p_slot` at start and an unheld slot refuses (`LookaheadExhausted` →
`SignRefused`); the handler does **not** additionally gate on the
`HeldPersona::Bonded` tag, because that tag is a reconcilable persistence
hint (`types.rs`) and the host already cannot start without a connected bond
record — a second gate on a hint would add false refusals and no security;
`PassKey::sign_pass` stays synchronous (no `shekyl-p-serve` API churn);
`shekyl-p-host` re-exports `SignRefused` and `sign_pass_transcript` beside
`PassKey` so `engine-core`'s dependency set does not change.

## 4. §9.7 item 3 — status, and a question surfaced by this pre-flight

The closure criterion was written against `ServeSet::from_connected_record`,
which no longer exists; `ServeSet` is now sealed (`pub(crate)` constructors,
minted only by `PinnedServeSet::acquire`). What `acquire` consumes is a
`ReportedSet`, a public enum returned by the `ServeSetPinner` trait — so the
fabrication path the item names is today "a different `ServeSetPinner`
implementation", injected at the single `spawn_serving_task` call site.
The literal-struct hazard the item describes is real for `ReportedSet` and
closed for `ServeSet`.

Discharging it as written means a sealed record type minted only by the
claim-source decode (`shekyl-archival-retention`), a `ReportedSet`
constructor that takes it, the production pinner in `engine-core` using
that, and a `cfg(test)` constructor for the task tests' fakes — a
provenance-sealing change across three crates, which is a different
validation surface (rule 19) from the resident key. **It is not built in
this PR.** Whether it lands as a following PR or is re-ruled against the
reopen criterion (one production pinner, reviewable by reading it) is put
to the maintainer with this record; the item's text in §9.7 is updated to
name `ReportedSet` either way, so the next reader does not re-derive this.

**RULED 2026-10-07 (maintainer, reading #990 at source) — re-ruled against
the reopen criterion; the seal is not built.** The only code that can
fabricate a `ReportedSet` runs inside the operator's own wallet process, so
the attacker is the operator against themselves; a fabricated set cannot
make `P` serve bytes it does not hold, and a pass for a shard outside `P`'s
bond is refused on chain by `J9` — the chain, not the wallet's report, is
authoritative. A wrong set can only make `P` fail its own challenges. One
production pinner (`serve_set_source.rs`) is what the criterion asks for.
**Dependency named:** the ruling stands on `J9` landing with SO-D8 Slice C;
until then `set_archival_settlement` has no production caller, so nothing is
exposed in the interval. **UPDATE 2026-10-08 (`SO-D10e`):**
`set_archival_settlement` is deleted; the C++ store has no settlement writer.
The Rust slash pass writes settlement rows, but no block path issues a draw
yet, so it has nothing to settle and the interval claim holds. The reopen criterion in §9.7 is unchanged. The
ruling's text of record is `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.7 item 3
(RULED 2026-10-07).

## 5. Part B disciplines

- **B1 / B4** — the proving test is the production call graph end to end
  (actor → `PassKey` → `HostSigner` → `PServeEndpoint` → `PFetchClient` →
  verifier). The height is the daemon-tip cache, stamped once for the test.
  No shape-only assertion stands in for the signature verifying.
- **B2 / B3** — no `pub` widened for tests: the `PassKey` impl and the
  handle method are `pub(crate)`; the test uses the same `StakeEngineHandle`
  path production does. `HostSigner` stays `pub(crate)`.
  `signer_at_synced_tip` is re-exported on the same `test-signer` edge as
  `RefusingKey`. `shekyl-p-host`'s two production re-exports have the
  production consumer (`engine-core`) in this PR.
- **B5** — each commit builds and passes `cargo clippy --all-targets
  -D warnings` on its own.
- **B6** — `PASS_COUNTERSIGNATURE_MESSAGE_LEN = 112` read at
  `shekyl-archival-retention/src/pass_anchor.rs`; `IDENTITY_ENVELOPE_LEN =
  HybridSignature::CANONICAL_LEN` at `countersign.rs` — the envelope width of
  the identity key, the scheme every live endpoint is bound at. (Read on
  2026-10-06 as `SIGNATURE_ENVELOPE_LEN`, then the one global width; it was
  replaced when the width became the bound scheme's, `FN_DSA_HYBRID.md`
  §9.3, `FND-21`.) No new constant is minted.
- **B9** — the budget the sign has to fit is the client's 30 s `body_stall`;
  the hybrid sign is sub-second on the floor and the only other term is one
  scan-step mailbox wait. No new bench is prescribed; `BA-T5` owns per-phase
  serve cost and is unaffected by which key signs. *Not measured, by ruling
  (2026-10-07):* a timing of the current key would measure the ML-DSA-65
  hybrid that the Slice C Round 0 ruling replaces with an FN-DSA-1024 receipt
  key (§6), and the floor device is the **daemon** floor, not a serving floor
  — nobody serves from it. When it is measured, it is FN-DSA-1024 sign on a
  serving-class host. (A dev-box reading of the production
  `sign_pass_transcript`, taken while setting that run up: p50 ≈ 0.4 ms, p99
  ≈ 1.8 ms, n = 50 — four orders under the budget, and not the key that
  ships.)

## 6. What this PR leaves owed

- **The receipt key on the serve path — STAGED; selection is owed to the
  settlement lane's cutover (`FN_DSA_HYBRID.md` §9.4).** The Slice C Round 0
  ruling (maintainer's brief, 2026-10-07) puts a **separate FN-DSA-1024
  receipt key** in the bond record and keeps identity on ML-DSA-65. The bond
  record carries it as `receipt_sign_pk`
  (`rust/shekyl-types/src/archival/bond.rs`). The stake actor has two
  signing messages, side by side:
  - `SignPassTranscript`
    (`rust/shekyl-engine-core/src/engine/stake_engine/persona.rs:210`) signs
    with the bond identity key, `hybrid_sign_sk`, through
    `sign_pass_transcript`: hybrid scheme 1, `SCHEME_DOMAIN_ATTESTATION`
    (`persona.rs:232`). This is the path this PR built. It is unchanged.
  - `SignReceiptTranscript` (`persona.rs:268`) signs with the receipt key,
    `receipt_sign_sk`, through `HeldPersona::sign_receipt_transcript`
    (`stake_engine/types.rs:167`): hybrid scheme 3, `SCHEME_DOMAIN_RECEIPT`.
    The key is decoded into `HeldReceiptKey` by the first signature asked
    of the persona.

  Each message has its own serving capability. `ResidentPassKey`
  (`stake_engine/serving/pass_key.rs:70`) is a `PassKey` at the identity
  width and is **live**: `serving/start.rs:257` hands it to the serving
  task. Its proving test, `signs_under_the_bond_identity_key`
  (`pass_key.rs:160`), describes the live path. `ResidentReceiptKey`
  (`stake_engine/serving/receipt_key.rs`) is a `PassKey` at the receipt
  width and is **built and not selected**: no production code constructs
  it, the `expect(dead_code)` on `ResidentReceiptKey::new` fails the lint
  lane if one does, and `the_serving_task_is_not_started_with_the_receipt_key`
  reads `start.rs`. Its proving tests are
  `signs_under_the_receipt_key_and_the_receipt_domain` and
  `a_receipt_is_not_an_identity_signature`. `receipt_round_trip_tests.rs`
  runs it behind the real endpoint, and each scheme's fetch target refuses
  the other scheme's endpoint
  (`the_two_schemes_do_not_accept_each_others_endpoints`).

  The receipt capability has this PR's shape: in-actor signing, the key
  never leaving `HeldPersona`, a weak handle and a slot, and `ready()` as
  actor liveness without a round-trip. Its `ready()` also refuses once a
  signature has found the receipt key undecodable. It runs behind the same
  loopback harness (`shekyl-p-loopback`). `RefusingKey` is a `PassKey` at
  the identity width only (`rust/shekyl-p-host/src/signer.rs:97`). The
  transcript is the same 112 bytes for both keys; the signature's own
  scheme byte names the scheme (`FN_DSA_HYBRID.md` §1). `persona.rs:189`'s
  doc comment that
  `hybrid_sign_sk` authorises three things holds while the identity key
  signs the pass. The receipt key signs only through
  `sign_receipt_transcript`, which fixes the receipt domain. What is owed
  is selection — the host's key width, the construction at
  `serving/start.rs:257`, and the daemon's fetch targets over
  `receipt_sign_pk` — in the change that makes a verifier accept scheme-3
  receipts. `FN_DSA_HYBRID.md` §9.4 owns that list.
- ~~`BENCHMARK_ALIGNMENT.md` §S's default ("S, with the pre-flight method")
  stays the maintainer's to rule; this PR supplies the answer §S was waiting
  on.~~ **RULED on `dev` before this PR merged** (maintainer, 2026-10-05;
  built by #974/#982, recorded by #987): S as an abuse mitigation, with the
  key's pre-flight among the constant work before the head. This PR's
  §3 Q2 answer is consistent with it, and `BA-T5` now owes the cost by
  phase, not the ruling.
- ~~§9.7 item 3's `ReportedSet` sealing — a maintainer decision.~~ RULED
  2026-10-07, not built (§4).
