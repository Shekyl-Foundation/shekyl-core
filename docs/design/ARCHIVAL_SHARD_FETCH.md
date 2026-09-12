# Archival shard fetch — the daemon client (design round)

**Status: OPEN.** Round 1 opened 2026-09-12, grounded `dev@ba4b3c73a`.
Identifier family `SF-` (index row `SF-D1…SF-Dn`, registered at birth per
rule 94 §1). Process per
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
this is a multi-round design front on an FFI-adjacent, privacy-load-bearing
surface. Decision authority: Rick. **No implementation code — no fetcher,
no Tor outbound API, no FFI — until `SF-D2`…`SF-D9` are RULED** (rule 26
halt on undischarged named pass). The FOLLOWUPS row is the deferral
record.

This round specifies the **client** side of the archival serving route:
a daemon fetching `GET /shard/{id}` from a P-served `.onion`. The server
half exists (`shekyl-p-serve` + `shekyl-p-host`, built-unwired at SH-1/
SH-2); the bytes are ruled (`RF-D4` frame, `RF-R1` route); discovery is
ruled (`EU-D1`…`EU-D9`). What has never been ruled is dial, isolation,
timeout/retry, verify seam, and where the client lives — the things an
implementer would otherwise decide silently at the keyboard.

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
**not** license a fake challenge path in the meantime. Full nodes that
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
| Daemon Tor today | `rust/shekyl-tor-control-daemon` crate doc — inbound ephemeral onion only (PWD-E7); no outbound API, no SOCKS consumer | `SF-D2`'s starting state |
| Discovery | `EU-D3`/`EU-D4` — endpoint = raw 32-byte Ed25519 key on the bond record; witness reads it from the drawable snapshot at epoch open, joined by `p_id` (`DrawablePair`, `rust/shekyl-archival-retention/src/challenge_assignment.rs:71`) | `SF-D5`'s input: key → onion is derivation, not lookup |

## 4. Already closed — do not re-litigate

| Premise | Where |
|---|---|
| Test **is** a read; miners are ordinary clients; a distinguishable challenge path is teaching-to-the-test | TJ §9, §9.1 |
| Witness = producer of block *h* | Challenge mechanism fork 2 (ruled 2026-08-10) |
| Daemon is client; wallet is server; no wallet-to-wallet; HTTP-over-onion not a Levin message; RPC a separate layer; fetcher beside `shekyl-daemon-rpc` | `EU-D1` |
| Endpoint = raw 32-byte Ed25519; address is display form; discovery is a chain read at the epoch-open drawable snapshot | `EU-D3`, `EU-D4` |
| Enumerability of onions is a design input; serve-side rate-limit is load-bearing | `EU-D6` |
| `GET /shard/{id}`; identical 404s for every non-servable outcome; only content-type + content-length; hand-rolled HTTP/1.1 | `RF-R1` |
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

## 6. Round-1 open questions (`SF-D2`…`SF-D9`)

Each is recorded with a **lean** and a **reopen criterion**; none is
ruled here. Rick rules them; the doc does not pre-decide.

### `SF-D2` — daemon Tor outbound posture

`shekyl-tor-control-daemon` is inbound ephemeral-onion only (PWD-E7);
it exposes no outbound API and no SOCKS consumer. Question: reuse the
managed instance's SOCKS port for fetches, or run a second Tor process
so overlay P2P and archival fetches do not share entry guards?

- **Lean:** reuse the managed instance, with `SF-D3` isolation carrying
  the separation — a second Tor process is a second failure domain and
  a second version to supervise on the Pi 4 floor (rule 76), and the
  shared-guard residual is already named next to `EU-D1` / SPIKE-F-12.
- **Reopen if:** measurement over this topology (the SP-T3 re-base)
  shows guard-level correlation of P2P identity with the fetch set that
  stream isolation cannot cut.

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

### `SF-D9` — `RF-R1` heading correction

Not a protocol decision. Same-change doc task (rule 91): retitle the
living contract ([`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md))
as daemon→P HTTP-over-onion, cite `EU-D1`, leave the byte rules —
path, status/headers, request grammar, transport, falsifier —
untouched. **Done in this change.** The heading the contract carried
before `EU-D1` ruled the client side is this section and the SHA of
#714, not a parenthetical in the living contract.

## 7. Threat-model frame (rule 26 A3)

Named attacker objectives this round's rulings are evaluated against:

1. **`P` teaching-to-the-test.** Any client behavior that distinguishes
   a challenge fetch from an organic read — a second path, a
   caller-shaped header or path token, a challenge-shaped isolation
   key, a caller-correlated retry pattern — lets `P` serve the test and
   refuse the job. This is TJ §9's attack, now applied to the client's
   observable surface.
2. **Guard sees the fetch set.** A daemon fetching many personas on one
   SOCKS identity exposes the challenge schedule and reconstruct
   traffic to a single entry guard (`SF-D3`).
3. **Rate-limit as DoS on coverage.** The serve-side rate limit is
   load-bearing (`EU-D6`); a client whose retry/concurrency shape lets
   a hostile `P` (or a hostile third party filling `P`'s limiter) push
   honest challenge fetches past the consensus deadline converts a
   privacy defense into a slash weapon (`SF-D6`/`SF-D7`).
4. **Shared-guard P2P + archival correlation.** If overlay P2P and
   archival fetches share entry guards, a guard-level observer
   correlates daemon identity with fetch interest (`SF-D2`; residual
   named next to `EU-D1` / SPIKE-F-12).

## 8. Explicitly out of this round (rule 19)

- **TJ-D storage:** DRS coupling, segment-freeze leaf-exclusion / chunk
  store, actually discarding local leaves. Not the fetch client (§2.1).
- Pass-record tx carrier, countersignature, prunable residence (format
  HOLD list / [`ARCHIVAL_PASS_RECORD_CARRIER.md`](ARCHIVAL_PASS_RECORD_CARRIER.md)).
- Settlement writer (`SO-D*`, still OPEN).
- The remaining EU landing sequence (A, B+C1, D).
- Vin-carried opening deletion (TJ-1 closer; a consensus cutover, not
  this client).
- W₂ numeric pin and the `(m, n)` re-pin — both need this topology
  measured first (the SP-T3 re-base is the pre-flight of the
  implementation PR, not part of this round).
- SH-2 remainder (the wallet actually constructing
  `PersonaServingHost`) — a named blocker for *end-to-end onion
  integration*, not for specifying the client; loopback serve already
  tests the HTTP half.
- The endpoint field on the vin (EU's B+C1 slice).

## 9. What "ruled" looks like after Round 1

A living contract the first **client** is written against: crate name,
Tor posture, isolation key both callers can use, dial grammar
(key → onion:port), one failure taxonomy with two caller columns, and
the verify function signature. The challenge is a scheduler of that
client. The W₂ measurement plan is named as Round 0 / pre-flight of the
*implementation* PR, over daemon→wallet — never as a second protocol
round. The first implementation is the client; the first tests are that
client against `shekyl-p-serve`; the challenge caller is wired to the
same entry point.
