# Archival shard fetch — the daemon client (design round)

**Status: OPEN.** Round 1 opened 2026-09-12, grounded `dev@ba4b3c73a`.
Identifier family `SF-` (index row `SF-D1…SF-Dn`, registered at birth per
rule 94 §1). Process per
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
this is a multi-round design front on an FFI-adjacent, privacy-load-bearing
surface. Decision authority: Rick. **No implementation code — no fetcher,
no Tor outbound API, no FFI — until `SF-D2`…`SF-D10` and `SF-D12` are
RULED** (rule 26 halt on undischarged named pass; `SF-D10`/`SF-D12` are
one ruling; `SF-D11` withdrawn, §4). The FOLLOWUPS row is the deferral
record.

This round specifies the **client** side of the archival serving route:
a daemon fetching `GET /shard/{id}` from a P-served `.onion`. The server
half exists (`shekyl-p-serve` + `shekyl-p-host`, built-unwired at SH-1/
SH-2); the bytes are ruled (`RF-D4` frame, `RF-R1` route); discovery is
ruled (`EU-D1`…`EU-D9`). What has never been ruled is dial, isolation,
timeout/retry, verify seam, where the client lives, **which P an organic
caller dials** — verify-failure memory is an input to that rule, not a
separate question (`SF-D10`/`SF-D12`) — the things an implementer would
otherwise decide silently at the keyboard.

**Grep-surface conventions.** A withdrawn *identifier* is current
information: keep `SF-D11` WITHDRAWN in the heading and in §4, so a
future grep finds the withdrawal. A superseded *phrase* is not: delete
it from the live surface (the RF-R1 heading, a comment that stated a
retracted residual). The SHA is the archive. They look contradictory
if you have not asked which one a future grep needs to find: the id,
yes; the old wording, no.

---

## 1. Lineage — the remainder EU-D1 and TJ §9.4 both pointed at

[`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`](ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md)
§9.4 restated TJ-B as "the client-facing read/serve protocol." Since
then, the format half landed as `RF-D1`…`RF-D10`
([`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md)), the
request line landed as `RF-R1`
([`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md)), and
discovery landed as the `EU-` round
([`ARCHIVAL_ENDPOINT_UPDATE.md`](ARCHIVAL_ENDPOINT_UPDATE.md), ruled
2026-09-11). TJ-B as a bucket is spent. What remains — and what this
round is — is the **daemon client of those contracts**.

`EU-D1` made the gap load-bearing rather than latent:

- **Server exists, client does not.** `shekyl-p-serve` answers
  `GET /shard/{id}` on loopback; the `RF-R1` freeze clock (earliest of
  production fetcher, published descriptor, genesis tag) has **not**
  fired — there is no production fetcher.
- **Bytes are specified; the client protocol is not.** `RF-D4` owns the
  body, `RF-R1` owns the request line. Neither owns dial, isolation,
  timeout, retry, or how a daemon Tor instance is used outbound.
- **The topology flipped.** `EU-D1` rules: the daemon is the client; no
  wallet talks to a wallet; the fetcher is a daemon Rust subsystem
  beside `shekyl-daemon-rpc`; the shard route stays HTTP-over-onion,
  not a Levin/P2P message; RPC is a separate layer. `EU-D1` also
  records that SP-T3 measured the wrong topology (persona→persona; the
  protocol is daemon→wallet) and owes a re-base before promotion to
  challenge substrate.

## 2. Hard line: one client; the challenge is a caller of it

TJ §9 ruled the test **is** a read — same payload, same ask, or `P`
fast-paths the harness. `EU-D1` put every ask on a daemon. Together:
there is **one** protocol to specify. A miner who produced block *h* is
one caller ("fetch leaf ℓ of shard *s*"). A daemon that needs the shard
(reconstruct, IBD-after-prune, operator test) is another caller. They
share the fetcher; they do not get a second path.

This is not a sequencing preference. A challenge-only client is exactly
the distinguishable harness TJ §9.1 forbids, and it is also
**untestable structure**: the serve path has no honest counterparty
until a client exists. While the server is being built, the client is
how you test it. There is no other way.

### 2.1 TJ-D does not defer this

TJ §3 split *verify semantics* (genesis-frozen) from *pruning mode*
(node-local storage, "whenever after"). TJ-D itself is that storage
work: DRS coupling, segment-freeze reconciliation, dissolving
consensus-required leaf retention. **"Post-genesis" is a hard line on
the storage mode, not a plan for the fetch client.** TJ-D bundled "who
asks P for bytes" with "when daemons discard leaves"; those are
different artifacts:

| Artifact | When | This round |
|---|---|---|
| Daemon fetch client (dial, isolate, GET, verify against local `R_k`) | **Now** — the structure has no test without it; the challenge has no honest path without it | **In** — this is the round |
| Challenge as a caller of that client | **Now** — same mechanism | **In** — a caller, not a second protocol |
| Prune-mode (actually discard local leaves) | When TJ-A has dissolved local-leaf verify; node-local, no coordinated upgrade | **Out** — TJ-D storage; another *caller* of the same client when it lands, not a later protocol |

TJ's R2 still holds: until prune-mode exists, every daemon already has
the leaves, so the market's scarcity product is not live. That does
**not** license a fake challenge path in the meantime. Nodes that
still hold every leaf still fetch-and-verify over the onion — that is
how serving is tested, and that is how challenges run. This section
exists so the index's "pruning MODE ships post-genesis" line cannot be
inherited as "the client waits."

## 3. Substrate (verified at source, 2026-09-12, `dev@ba4b3c73a`)

| Pin | Where | What it fixes |
|---|---|---|
| Serve route | `rust/shekyl-p-serve/src/serve.rs:57` — `ROUTE_PREFIX = "/shard/"` | The path the client dials (`RF-R1`) |
| Served body | `rust/shekyl-curve-tree/src/served_frame.rs:274` — `ServedFrameHeader::read` | Frame parse incl. the `RF-D7` padding bound, enforced before the lengths are obtainable |
| Verify function | `rust/shekyl-curve-tree/src/store/ops.rs:139` — `recompute_segment_r_k(&[[u8; 128]]) -> Result<[u8; 32], _>` | Self-authentication by reconstruction; today its only non-store caller is `p-serve/tests/store_axis.rs` — no production fetcher |
| Serve virt port | `rust/shekyl-engine-core/src/engine/stake_engine/serving/task.rs:52` — `SERVING_VIRTUAL_PORT = 80`; `:58` — `SERVING_MAX_STREAMS = 8` | **Unratified** (tests-only consensus); `SF-D5` pins or rejects the port; `MAX_STREAMS` stays SPIKE-PIN territory |
| Challenge deadline | `rust/shekyl-archival-retention/src/constants.rs:147` — `CHALLENGE_RESPONSE_BLOCKS = SEB / 20 = 500` | The consensus clock the challenge caller answers to (`SF-D6`) |
| Wallet-side isolation precedent | `rust/shekyl-p-transport/src/lib.rs:134` — `derive_socks_user(&PCanonicalId)` per-P `IsolateSOCKSAuth` | The isolation grammar `SF-D3` must adapt: a daemon is not a P |
| Daemon Tor today | `rust/shekyl-tor-control-daemon` crate doc — inbound ephemeral onion only (PWD-E7); no outbound API, no SOCKS consumer | `SF-D2`'s starting state: outbound reuse can only mean **this** instance |
| Discovery | `EU-D3`/`EU-D4` — endpoint = raw 32-byte Ed25519 key on the bond record; witness reads it from the drawable snapshot at epoch open, joined by `p_id` (`DrawablePair`, `rust/shekyl-archival-retention/src/challenge_assignment.rs:71`) | `SF-D5`'s input: key → onion is derivation, not lookup |
| Request parse | `rust/shekyl-p-serve/src/serve.rs:558–560` — `path.strip_prefix(ROUTE_PREFIX)` then `parse::<u64>()`; comment: "Exact decimal id — no path suffix, no query string" | The request unit is a whole shard (`§4`) |
| Segment size | `rust/shekyl-curve-tree/src/segment.rs:36` — `LEAF_BYTES`; `:63` — `leaves_per_segment()` | Honest-holder egress of a challenge fetch: one full segment (`leaves_per_segment() × LEAF_BYTES`) |
| Serving ↔ fetching Tor | `PWD-E9` ([`P2P_2_ENDPOINT_ROUND.md`](P2P_2_ENDPOINT_ROUND.md) §PWD-E9): daemon gets its own tor path, no crossover to the archival-serving persona; launch path takes instance identity as a parameter. Implemented 2026-09-09 (`DaemonTorControl`, `shekyl-tor-control-daemon`) | Closed. Constrains `SF-D2`: "reuse the managed instance" means the daemon's |
| Intro-layer PoW | `rust/shekyl-tor-control-wallet/src/onion_service.rs:146–148` — `HiddenServicePoW` defaults **on**; `rust/shekyl-tor-control-client/src/control/onion.rs:272–292` — PoW throttles rendezvous **arrival**, not egress; over onion the body transfer is symmetric (flow control). `control/actor.rs:1725–1754` — live `ADD_ONION` with PoW. Measurement: [`SP_T3_SKELETON_MEASUREMENT.md`](SP_T3_SKELETON_MEASUREMENT.md) SPIKE-F-15/17/18, §19/§19a | Threat-3 pin: intro flooding is priced; not general Tor lore |

## 4. Already closed — do not re-litigate

| Premise | Where |
|---|---|
| Test **is** a read; miners are ordinary clients; a distinguishable challenge path is teaching-to-the-test | TJ §9, §9.1 |
| Witness = producer of block *h* | Challenge mechanism fork 2 (ruled 2026-08-10) |
| Daemon is client; wallet is server; no wallet-to-wallet; HTTP-over-onion not a Levin message; RPC a separate layer; fetcher beside `shekyl-daemon-rpc` | `EU-D1` |
| Endpoint = raw 32-byte Ed25519; address is display form; discovery is a chain read at the epoch-open drawable snapshot | `EU-D3`, `EU-D4` |
| Enumerability of onions is a design input; serve-side rate-limit is load-bearing | `EU-D6` |
| `GET /shard/{id}`; identical 404s for every non-servable outcome; only content-type + content-length; hand-rolled HTTP/1.1 | `RF-R1` |
| **Request unit is a whole shard.** `{id}` is an exact decimal `u64`; no suffix, no query string (`RF-R1` request grammar; `serve.rs:558–560` parses exactly that). There is no leaf addressing. The challenge caller fetches the full segment and extracts leaf ℓ locally — that is the TJ §9 topology working as designed (the honest holder's egress is the cost being measured). `RF-R1`'s reopening clause permits "an additional path that suffixes `/shard/`" if a later request contract is needed; that suffix is exactly where a leaf-addressed challenge fetch would enter, and it is the natural optimization for anyone looking at ~3.33 MB per challenge. **`SF-D1` holds that door shut:** any future suffix path must be usable by both callers, or it is a second path by another name | `RF-R1`; `SF-D1` |
| **Serving and fetching do not share a Tor instance.** `PWD-E9` (RULED 2026-09-08, implemented 2026-09-09): the daemon gets its own tor path with no crossover to the archival-serving persona; the launch path takes instance identity as a parameter, so sharing the code cannot produce a shared instance. The ratified §7 guard residual splits one application's identities; E9 forbids two applications sharing one instance, and the ephemeral/durable asymmetry makes the crossover strictly worse. **`SF-D11` withdrawn** — asked in this round, then closed by reading `PWD-E9` | `PWD-E9` |
| Body = `ServedFrameHeader` (leaf_count ‖ padding_len ‖ segment ‖ padding); codec owned by `shekyl-curve-tree`; write-zero read-anything | `RF-D4`, `RF-D7` |
| Padding field reserved, no scheme; TJ-H mitigation at the Tor layer (vanguards on the **wallet** serve path) | TJ-H (ruled 2026-08-08) |
| Server bind `127.0.0.1:0`; reachability is `ADD_ONION` | `RF-R1`, `shekyl-p-host` |
| SP-T3's numbers measured persona→persona and must re-base daemon→wallet before promotion | `EU-D1` consequence 4 |

## 5. `SF-D1` — premised at open, not asked

**One client protocol. The challenge fetch and the organic read are both
callers of it.** No third wallet-side client; no challenge-only harness;
no caller-specific header, path token, or isolation shape that would let
`P` distinguish a test from a read. Two production schedulers drive the
same entry point — "you produced block *h*: fetch leaf ℓ of shard *s*"
and "this daemon needs shard *s*" — and tests are a third scheduler of
that same entry point, not a separate path.

Reopen if a storage-only pruned-daemon path is shown to exercise the
serve endpoint end to end without a fetch client. (Also if `EU-D1` or
TJ §9 is itself reopened — those are the substrate this premise sits
on, not a substitute for a local falsifier.)

**Latch on the `RF-R1` suffix door (§4).** A later request contract that
suffixes `/shard/` is a named reopening of `RF-R1`, not of this round —
and it inherits this premise: the new path must be usable by both
callers. A leaf-addressed challenge-only suffix is a second path.

## 6. Round-1 open questions (`SF-D2`…`SF-D8`, coupled `SF-D10`/`SF-D12`)

Each is recorded with a **lean** and a **reopen criterion**; none is
ruled here. Rick rules them; the doc does not pre-decide. `SF-D9` is
done (same-change heading). `SF-D11` is withdrawn (§4 / `PWD-E9`) and
is not in this list. `SF-D10` and `SF-D12` are one row: ruling them
separately will produce an inconsistency.

### `SF-D2` — daemon Tor outbound posture

`shekyl-tor-control-daemon` is inbound ephemeral-onion only (PWD-E7);
it exposes no outbound API and no SOCKS consumer. Question: reuse the
managed instance's SOCKS port for fetches, or run a second Tor process
so overlay P2P and archival fetches do not share entry guards?

- **Lean:** reuse the daemon's managed instance, with `SF-D3` isolation
  carrying the separation — a second Tor process is a second failure
  domain and a second version to supervise on the Pi 4 floor (rule 76),
  and the shared-guard residual is already named next to `EU-D1` /
  SPIKE-F-12. Serving↔fetching is not this question (`PWD-E9`).
- **Reopen if:** measurement over this topology (the SP-T3 re-base)
  shows a reason the accepted residual is worse than a second Tor
  process at the Pi 4 floor.
- **Note:** guards are per-process. Stream isolation (`SF-D3`) cannot
  cut a shared-guard residual on one Tor instance, so an earlier draft
  of this reopen ("correlation that stream isolation cannot cut")
  described the lean rather than a later measurement. **"Reuse the
  managed instance" can only mean the daemon's** — `PWD-E9` closed the
  serving↔fetching axis (`SF-D11` withdrawn, §4), so this question is
  genuinely the P2P ↔ archival-fetch pair inside the daemon.

### `SF-D3` — circuit-isolation key

The wallet precedent is per-P `IsolateSOCKSAuth`
(`derive_socks_user`). A daemon fetching many personas' shards on one
SOCKS user lets one guard see the whole fetch set — the challenge
schedule **and** reconstruct traffic. Candidate keys: per-fetch,
per-`(P, s)`, per-block, none (accepted residual).

- **Lean:** per-fetch (fresh isolation credential per request) unless
  circuit-build cost at the Pi 4 floor forces coarser; per-`(P, s)` is
  the fallback.
- **Constraint (from `SF-D1`):** the key must be computable by **both**
  callers from inputs both possess. A challenge-shaped key (e.g. keyed
  on the block hash that only the challenge caller has) is a second
  path.
- **Reopen if:** Tor circuit-build latency at the floor makes per-fetch
  isolation exceed the `SF-D6` budget for the challenge caller.

### `SF-D4` — crate home

`EU-D1` fixed the side: daemon, Rust, beside `shekyl-daemon-rpc`. This
round names the crate and the C++ shim (rule 20: logic in Rust; the C++
is a transport/marshaling shim over a `shekyl_*` entry point). The shim
has **two** production schedulers, not one. The client must **not**
live in `shekyl-p-serve` (the server crate; `RF-D4` already refused
format ownership by the server) and must not pull engine-core.

- **Lean:** a dedicated `shekyl-shard-fetch` crate — the two schedulers
  and the test harness are three consumers, which is the multi-site
  shape that justifies a crate boundary; inside `shekyl-daemon-rpc` it
  would inherit an RPC-surface review posture it does not need.
- **Reopen if:** the crate turns out to be one file with one consumer
  at implementation time — then folding into the daemon subsystem is a
  doc-comment decision, re-ruled at the implementation PR's pre-flight.

### `SF-D5` — dial grammar

Reconstruct the v3 onion address from the 32-byte Ed25519 key
(`EU-D3`: the address is display form; the key is the record). Pin the
virtual port — today `SERVING_VIRTUAL_PORT = 80`, a tests-only
consensus that has never been ratified. SOCKS CONNECT to
`onion:port`, then the `RF-R1` GET. No extra request headers (already
`RF-R1`'s rule) and no caller-specific path token (`SF-D1`).

- **Lean:** ratify port 80 (it is the conventional HTTP virt port,
  carries no fingerprint beyond the route itself, and every existing
  test and the serve task already speak it).
- **Reopen if:** the Tor layer surfaces a reason a non-default virt
  port cuts an enumeration or scanning class `EU-D6` cares about.

### `SF-D6` — timeout / miss / retry taxonomy

The consensus deadline exists (`CHALLENGE_RESPONSE_BLOCKS = 500`) and
binds the challenge caller. W₂ (the honest-serve bound) is **not** this
round's to pin — it is a measurement over **this** topology, owed by
the SP-T3 re-base. This round specifies *shape*: which of {circuit
timeout, HTTP stall, identical 404, malformed frame, `R_k` mismatch,
unpublished onion} is a **challenge miss**, a **client-need fault**
(retry/backoff for reconstruct), a **witness-local fault**, or
**retryable**.

- **Lean:** one table, two caller columns — what the challenge caller
  does vs what the need-shard caller does. Identical 404 and `R_k`
  mismatch land as miss for the challenge caller (the server's identical
  404 is deliberate; the client cannot and must not distinguish why);
  circuit timeout and unpublished onion get bounded retries inside the
  deadline; malformed frame is a miss (the `RF-D7` bound already makes
  refusal cheap and pre-allocation).
- **Constraint:** retries must not become a distinguishable challenge
  pattern — the retry policy is a property of the client, not of the
  caller.
- **Reopen if:** the W₂ measurement shows the retry budget and the
  consensus deadline cannot coexist at the floor.

### `SF-D7` — concurrency vs growing `D`

Server-side `MAX_INFLIGHT` / `max_streams` remain SPIKE-PIN-1/2 (the W₂
rig's). The client needs its own in-flight bound at the Pi 4 floor
(rule 76), sized for **both** callers sharing one daemon Tor instance.
Challenge mechanism §9.6 item 3 stands: `D` is unbounded; constants are
functions of `D`, not plateaus.

- **Lean:** a small fixed client-side in-flight cap with a queue,
  derived from the floor's circuit-build throughput, stated as a
  function of measured circuit cost — not a per-`D` scaling constant.
- **Reopen if:** coverage math at maturity (`D ≈ 324k`-era figures)
  shows a fixed cap starves the challenge caller inside
  `CHALLENGE_RESPONSE_BLOCKS`.

### `SF-D8` — verify seam

The fetcher's output is a **typed result both callers consume**: frame
parse (`ServedFrameHeader::read`) plus `recompute_segment_r_k` against
the daemon's local `FrozenSegmentRecord` / `R_k`. No store handle at
verify time (TJ-F liveness). Pass-record construction is **out of
scope** — the type this round names is the input that round consumes.
Reconstruct's "install these leaves" is also out of scope (TJ-D
storage); it consumes the same typed result.

- **Lean:** verify inside the fetch call (the client returns only
  verified-or-refused, never raw bytes) — a raw-bytes return is an
  invitation for a caller to skip the check, and both callers need the
  same verdict anyway.
- **Reopen if:** the reconstruct caller demonstrates a need for the
  unverified stream (e.g. partial-segment resume) that cannot be met
  behind the seam.

Whether the client **remembers** a refusal is an input to `SF-D10`,
not a follow-on (`SF-D12` is that input).

### `SF-D9` — `RF-R1` heading correction

Not a protocol decision. Same-change doc task (rule 91): retitle the
living contract ([`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md))
as daemon→P HTTP-over-onion, cite `EU-D1`, leave the byte rules —
path, status/headers, request grammar, transport, falsifier —
untouched. **Done in this change.** The heading the contract carried
before `EU-D1` ruled the client side is this section and the SHA of
#714, not a parenthetical in the living contract.

### `SF-D10` / `SF-D12` — organic selection (verify-failure memory is an input)

The challenge caller has no choice: the assignment names `(P, s)`. The
organic caller needs shard `s`, and `D` personas may hold it. Which one
does it dial? Random, deterministic-by-local-identity, and failover
order are three different privacy postures — deterministic means one
persona learns the daemon's entire need profile; random spreads the
disclosure across the set over time.

`SF-D8` returns verified-or-refused. An `R_k` mismatch on an organic
read means a persona served garbage. If the client remembers, that
memory has to act somewhere, and the only place it can act is organic
selection — the challenge dial is fixed by assignment. So verify-failure
memory is not a side condition on a later question: **it is a term in
this selection rule.** `SF-D12` names that term. Ruling the two
separately will produce an inconsistency (a selection rule that cannot
consume its own memory, or a memory that has nowhere legal to act).

This is a threat-#1 vector that request-shape uniformity does not
close. If organic reads are distributed across holders while challenge
fetches arrive at exactly the assigned one, a rarely-chosen `P` can
infer "I am rarely dialed organically, so this request is probably the
test." Teaching-to-the-test through selection statistics.

Memory that deprioritizes a persona *changes those statistics in a way
the persona can observe.* `P` serves garbage once, sees organic demand
fall off, and has now measured its own position in the selection
distribution. Repeat with a few daemons and `P` learns roughly how
often it should expect organic reads — which is the baseline it needs
to recognize an off-baseline request as a probable challenge. A naive
memory hands `P` a **calibration oracle** for free.

Whatever this rule is, the memory's effect on selection has to be
bounded so `P` cannot use its own exclusion as a measurement
instrument. Shapes that survive that bound:

- hard local exclusion with no partial deprioritization (binary, so
  there is no gradient to measure), or
- memory decays on a schedule `P` cannot infer, or
- selection is randomized enough that a single daemon's exclusion is
  below `P`'s observation noise.

Partial, durable, observable deprioritization does not survive.

- **Lean:** random among currently-bonded holders of `s` (fresh draw
  per organic fetch); **no durable exclusion** (the empty input — no
  calibration oracle). Organic retries are bounded by `SF-D6`. If
  memory is later shown necessary at the floor, it is re-ruled *as a
  term in this rule*, and only as one of the three surviving shapes —
  not as a follow-on that mutates a finished selection rule.
- **Constraint (from `SF-D1`):** the challenge caller does not consult
  this rule. The assignment is the selection. Memory, if it exists,
  cannot touch the challenge dial; a caller-blind exclusion list is a
  second path that refuses assigned tests.
- **Reopen if:** a holder, from its own request log alone — including
  by observing its own exclusion — can classify a request as challenge
  with better-than-assignment-base-rate confidence; or unbounded
  organic retry against a known-bad holder is shown to be worse, at
  the floor, than a surviving-shape exclusion.

### `SF-D11` — serving ↔ fetching Tor instance — WITHDRAWN 2026-09-12

Asked in this round, then closed by reading `PWD-E9` (RULED 2026-09-08,
implemented 2026-09-09). Not an open question and not in the halt list.
See §4. Identifier kept so grep finds the withdrawal; `SF-D12` is not
renumbered (already published).

### `SF-D12` — verify-failure memory — input to `SF-D10` (same row)

Not a separate question. The memory's only legal act-site is organic
selection; the constraint that it never touches the challenge dial is a
term of `SF-D10`, not a side condition here. See `SF-D10`. Identifier
kept so grep finds the coupling.

## 7. Threat-model frame (rule 26 A3)

Named attacker objectives this round's rulings are evaluated against:

1. **`P` teaching-to-the-test.** Any client behavior that distinguishes
   a challenge fetch from an organic read — a second path, a
   caller-shaped header or path token, a challenge-shaped isolation
   key, a caller-correlated retry pattern — lets `P` serve the test and
   refuse the job. This is TJ §9's attack, now applied to the client's
   observable surface.
   **Selection statistics are a second channel of the same attack**
   (`SF-D10`/`SF-D12`): request-shape uniformity does not close it. If
   organic reads are distributed across holders while challenge fetches
   arrive at exactly the assigned one, a rarely-chosen `P` classifies
   the request from its own log. Verify-failure memory is a term in
   that selection rule, not a later question: a memory that
   deprioritizes `P` is observable to `P`, and a naive one is a
   calibration oracle for the organic baseline.
2. **Guard sees the fetch set.** A daemon fetching many personas on one
   SOCKS identity exposes the challenge schedule and reconstruct
   traffic to a single entry guard (`SF-D3`).
3. **Slash-by-denial over onion — not a client-owned weapon, and not a
   handoff.** The serve-side limiter is load-bearing (`EU-D6`). The
   form that would slash is a third party keeping an *honest* `P`'s
   assigned challenge fetches from landing; the honest holder did
   nothing wrong, and the client cannot tell darkness from a full
   limiter (identical 404s, `RF-R1`). **Nothing this client can do is
   the defense,** and **nothing this round owes the challenge
   mechanism.** Volumetric denial over onion is symmetrically priced
   and untargetable; the cheap attack is positional and already owned.

   **Unobservability, not the window.** `CHALLENGE_RESPONSE_BLOCKS =
   500` is ~17 hours and sounds like a generous target. What defeats
   the attacker is that there is no target: the test is a read (`TJ`
   §9 / `SF-D1`), so nothing on the wire identifies which fetch is the
   challenge or when the assignment lands. They cannot attack a
   window — they have to attack continuously, across every window, and
   repeatedly, since one miss does not slash; the accumulated
   threshold does. `SF-D1`'s indistinguishability is also the anti-DoS
   property. Sustained intro-layer PoW cost against an unobservable
   target for a probabilistic payoff is a much worse trade than
   "saturate for 17 hours."

   **Intro PoW prices introductions; byte-rate after rendezvous is
   symmetric.** Proposal-327 PoW gates introductions
   (`onion_service.rs:146–148` defaults on; `control/onion.rs:272–292`
   throttles the rendezvous-request queue, not egress, and the body
   transfer is symmetric under flow control;
   `control/actor.rs:1725–1754` live `ADD_ONION` with PoW). Recollection is
   grounded in [`SP_T3_SKELETON_MEASUREMENT.md`](SP_T3_SKELETON_MEASUREMENT.md)
   SPIKE-F-15/17/18, not general Tor lore. Once a rendezvous is
   established, a whole-shard GET is ~3.33 MB. Over Tor the response
   traverses T's own three-hop circuit, and Tor's flow control means T
   has to keep acknowledging for data to keep flowing — stop reading
   and the circuit stalls and `P` stops sending. `P`'s egress is
   bounded by T's willingness to actually receive the body, through
   relays T is also paying for. It is symmetric, and each attack
   saturates everything from the rendezvous point on.

   **Who T would have to be, volumetrically.** Discovery is free
   (`EU-D3` puts the onion on chain). Targeting is unavailable
   (unobservability above). Introduction is priced per circuit, and T
   needs many concurrent circuits to hold a meaningful share of
   `EU-D6`. Sustain is the binding constraint: occupy most of the
   limiter continuously — sustained multi-megabit received throughput
   over Tor, across many circuits, each with its own guard and puzzle
   cost, for ~17 hours per window, for as many windows as the
   threshold requires. Payoff is capped at one persona's bond. Cost is
   unbounded in duration, symmetric in bandwidth, against a target
   whose challenge schedule T cannot see. The economically motivated
   version — a competing staker slashing a rival to raise emission
   share — is the worst fit of all. Any T with that capability has
   cheaper things to do with it.

   **The T that actually matters is positional, not volumetric.** An
   adversary selected as one of `P`'s layer-2 or layer-3 nodes can
   drop or delay rendezvous traffic at near-zero bandwidth cost,
   indefinitely, with no PoW to pay and no symmetric transfer. That
   is the cheap route to slash-by-denial over onion, and it is already
   owned: `VG-1`…`VG-3`, full-vanguards path selection for a serving
   persona, with the rotation state machine and the `VanguardsActive`
   sealed witness. The mechanism against the cheap attack exists;
   volumetric flooding is the expensive one.

   **If something does emerge, mitigation looks different than
   clearnet** — a response-time trap, not a design gap. The clearnet
   reflex is per-client throttling, and there is no client to
   throttle. Damage is not localized to `P`'s box (rendezvous
   outward). Four levers, no IP filtering: (1) Tor's intro-layer PoW
   parameters, (2) the service's own stream limiter (`EU-D6` /
   SPIKE-PIN-1/2), (3) vanguard posture (`VG-1`…`VG-3`), (4) the
   accumulated-miss threshold's tolerance. The mechanism-side answer,
   if one is ever needed, is the miss threshold; this round does not
   own a re-pin. `SF-D6`/`SF-D7` still own the client's own retry
   shape so it does not *add* distinguishable load; they do not own
   the slash.
4. **Shared-guard P2P + archival correlation.** If overlay P2P and
   archival fetches share entry guards, a guard-level observer
   correlates daemon identity with fetch interest (`SF-D2`; residual
   named next to `EU-D1` / SPIKE-F-12). Accepted-by-construction if
   they share a process (guards are per-process). Serving↔fetching
   (persona ↔ principal) is closed by `PWD-E9` (`SF-D11` withdrawn).

## 8. Explicitly out of this round (rule 19)

- **TJ-D storage:** DRS coupling, segment-freeze leaf-exclusion / chunk
  store, actually discarding local leaves. Not the fetch client (§2.1).
- Pass-record tx carrier, countersignature, prunable residence (format
  HOLD list / [`ARCHIVAL_PASS_RECORD_CARRIER.md`](ARCHIVAL_PASS_RECORD_CARRIER.md)).
- Settlement writer (`SO-D*`, still OPEN).
- The remaining EU landing sequence (A, B+C1, D).
- Vin-carried opening deletion (TJ-1 closer; a consensus cutover, not
  this client).
- W₂ numeric pin — needs this topology measured first (the SP-T3
  re-base is the pre-flight of the implementation PR, not part of this
  round).
- Failure-window `m`/`n` re-pin — already a FOLLOWUPS item, joint with
  reopen (d). This round adds no sizing input to it. Owner:
  `failure_window.rs` /
  [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](../completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md).
- Positional onion denial (`VG-1`…`VG-3`) and intro-layer PoW
  (`onion_service.rs`, `control/actor.rs`, SP-T3 SPIKE-F-15/17/18) —
  already owned; not this client. SPIKE-PIN-1/2 stay where `SF-D7`
  left them.
- SH-2 remainder (the wallet actually constructing
  `PersonaServingHost`) — a named blocker for *end-to-end onion
  integration*, not for specifying the client; loopback serve already
  tests the HTTP half.
- The endpoint field on the vin (EU's B+C1 slice).

## 9. What "ruled" looks like after Round 1

A living contract the first **client** is written against: crate name,
daemon Tor posture (P2P↔fetch; serving↔fetching already `PWD-E9`),
isolation key both callers can use, dial grammar (key → onion:port),
one failure taxonomy with two caller columns, the verify function
signature, and one organic selection rule of which verify-failure
memory is an input (`SF-D10`/`SF-D12`). The challenge is a scheduler of
that client. The W₂ measurement plan is named as Round 0 / pre-flight of
the *implementation* PR, over daemon→wallet — never as a second protocol
round. The first implementation is the client; the first tests are that
client against `shekyl-p-serve`; the challenge caller is wired to the
same entry point.
