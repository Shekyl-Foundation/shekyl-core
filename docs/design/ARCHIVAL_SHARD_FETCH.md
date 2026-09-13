# Archival shard fetch — the daemon client (design round)

**Status: RULED — Round 1 CLOSED 2026-09-13; implementation pending.**
Round 1 opened 2026-09-12, grounded `dev@ba4b3c73a`. Every `SF-D`
question is disposed: `SF-D2`, `SF-D3`, `SF-D4`, `SF-D6`, `SF-D7`,
`SF-D10`, `SF-D13` RULED; `SF-D5` RULED and amended with the request
carrier; `SF-D8` RULED (signed message and response carrier); `SF-D9`
done; `SF-D11` WITHDRAWN; `SF-D12` a corollary of `SF-D10`. **The
rule-26 halt is lifted:** the implementation PR (`shekyl-p-fetch`) may
begin. This file stays in `docs/design/` because it still owns named
residue the implementation PR discharges — the header spelling and
encoding (`SF-D5`), in-flight cap `N` (`SF-D7`), the signature domain
string and KAT (`SF-D8`), carrying the requester-random on the pass
record (`SF-D8`), and the W₂ measurement (§8) — and archives to
`docs/completed/` when the client lands. Organic draw bound `k` is
`TJ-D`'s, not this PR's.
Identifier family `SF-` (index row `SF-D1…SF-Dn`, registered at
birth per rule 94 §1). Process per
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
a multi-round design front on an FFI-adjacent, privacy-load-bearing
surface. Decision authority: Rick. The FOLLOWUPS row is the
implementation record.

This round specifies the **client** side of the archival serving route:
a daemon fetching `GET /shard/{id}` from a P-served `.onion`. The server
half exists (`shekyl-p-serve` + `shekyl-p-host`, built-unwired at SH-1/
SH-2); the inner frame and path are ruled (`RF-D4` frame, `RF-R1`
route); discovery is ruled (`EU-D1`…`EU-D9`). Timeout/retry is
`SF-D6` (RULED) and
concurrency is `SF-D7` (RULED). The request-side carrier and
countersigning key are now ruled (`SF-D5` amendment; `SF-D13`), and so
is the complete response (`SF-D8`, RULED 2026-09-13, amended later the
same day: both callers send requester-random bytes plus the published
tip height; `P` signs `nonce[32] ‖ height_le[8] ‖ shard_id_le[8]`; the
challenge tuple and `cb_out_key` are not in the fetch signature; the
response body is an outer binary envelope carrying the canonical
`HybridSignature` followed by the unchanged `RF-D4` frame) — the
things an implementer would otherwise have decided silently at the
keyboard. Crate home is `SF-D4` (RULED). Virt-port is `SF-D5` (RULED:
80, home `shekyl-curve-tree`). Outbound SOCKS reuse is `SF-D2`. SOCKS
isolation is `SF-D3` (unauthenticated, no isolation flags; circuit
assignment is Tor's).

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
- **The inner frame is specified; the complete countersigned response
  is not.** `RF-D4` owns the inner frame, `RF-R1` owns the current
  request line and HTTP status/headers. Neither owns timeout, retry, or
  dial grammar. `SF-D5` amends the request with the required nonce;
  `SF-D8` rules the response envelope. How the daemon uses Tor outbound
  is `SF-D2`. SOCKS isolation is `SF-D3` (unauthenticated, no isolation
  flags).
- **The topology flipped.** `EU-D1` rules: the daemon is the client; no
  wallet talks to a wallet; the fetcher is a daemon Rust subsystem
  beside `shekyl-daemon-rpc` (process locality, not crate membership —
  `SF-D4` names the crate `shekyl-p-fetch`); the shard route stays
  HTTP-over-onion, not a Levin/P2P message; RPC is a separate layer.
  `EU-D1` also records that SP-T3 measured the wrong topology
  (persona→persona; the protocol is daemon→wallet) and owes a re-base
  before promotion to challenge substrate.

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
| --- | --- | --- |
| Daemon fetch client (dial, GET, verify local `R_k` + P's countersignature over `nonce ‖ shard_id` — the nonce it sent, the shard it requested) | **Now** — the structure has no test without it; the challenge has no honest path without it | **In** — this is the round |
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
| --- | --- | --- |
| Serve route | `rust/shekyl-p-serve/src/serve.rs:57` — `ROUTE_PREFIX = "/shard/"` | The path the client dials (`RF-R1`) |
| Served body | `rust/shekyl-curve-tree/src/served_frame.rs:274` — `ServedFrameHeader::read` | Frame parse incl. the `RF-D7` padding bound, enforced before the lengths are obtainable |
| Content-verify function | `rust/shekyl-curve-tree/src/store/ops.rs:139` — `recompute_segment_r_k(&[[u8; 128]]) -> Result<[u8; 32], _>` | Content-authentication half only; today its only non-store caller is `p-serve/tests/store_axis.rs` — no production fetcher |
| Serve virt port | `rust/shekyl-engine-core/src/engine/stake_engine/serving/task.rs:52` — `pub(crate) SERVING_VIRTUAL_PORT = 80`; `:58` — `SERVING_MAX_STREAMS = 8` | **Number RULED 80** (`SF-D5`). `MAX_STREAMS` stays SPIKE-PIN. **Home** is `shekyl-curve-tree` (`SF-D4`); this `pub(crate)` is the current location, not the home — the implementation PR moves the declaration |
| Challenge deadline | `rust/shekyl-archival-retention/src/constants.rs:147` — `CHALLENGE_RESPONSE_BLOCKS = SEB / 20 = 500` | The consensus clock the challenge caller answers to (`SF-D6`) |
| Wallet-side isolation precedent | `rust/shekyl-p-transport/src/lib.rs:134` — `derive_socks_user(&PCanonicalId)` per-P `IsolateSOCKSAuth` | P↔principal firewall on the **wallet** Tor instance. `SF-D3` RULED: do not copy it onto the daemon fetcher |
| Overlay SOCKS credentials | `src/net/socks.cpp:246–271` — empty `userinfo` emits SOCKS5 no-auth | What overlay P2P presents on the managed instance. `SF-D3` matches it |
| Daemon `SocksPort` flags | `rust/shekyl-tor-control-client/src/control/actor.rs:859` — `--SocksPort` with `SocksPort::Auto`; no `Isolate*` flags on the spawn | Tor's own defaults apply. `SF-D3`: this client sets none |
| Daemon Tor today | SOCKS is discovered (`rust/shekyl-tor-control-daemon/src/ephemeral.rs:18` crate-doc; `:240` — `GETINFO net/listeners/socks`) and consumed (`src/p2p/net_node.inl:878` — `zone.m_connect = &socks_connect`; `:879` — `zone.m_proxy_address`). Default posture is inbound onion **plus** SOCKS outbound on the tor zone. `--tx-proxy` / `--anonymous-inbound` yield the managed instance (`net_node.inl:815–819`) | `SF-D2` RULED: reuse **this** zone proxy. Object of reuse is the zone's SOCKS, not always `DaemonTorControl`. Does not re-rule PWD-E7 |
| Discovery | `EU-D3`/`EU-D4` — endpoint = raw 32-byte Ed25519 key on the bond record; witness reads it from the drawable snapshot at epoch open, joined by `p_id` (`DrawablePair`, `rust/shekyl-archival-retention/src/challenge_assignment.rs:71`) | `SF-D5`'s input: key → onion is derivation, not lookup. `SF-D10` reads the holder set of `s` from the same snapshot |
| Derived assignment | [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §2: assignment for block *h* is a pure function of *h*−1's hash over the epoch-open drawable set. Public at *h*−1's publication; every node including `P` computes it identically. Witness = producer. Window = `CHALLENGE_RESPONSE_BLOCKS`. `attestation_nonce` is `H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` | Assignment stays derived. **It does not go on the fetch.** Both callers send requester-random bytes plus the published tip height (`SF-D5`). `attestation_nonce` is not a request field |
| Request parse | `rust/shekyl-p-serve/src/serve.rs:558–560` — `path.strip_prefix(ROUTE_PREFIX)` then `parse::<u64>()`; comment: "Exact decimal id — no path suffix, no query string" | The request unit is a whole shard (`§4`) |
| Segment size | `rust/shekyl-curve-tree/src/segment.rs:36` — `LEAF_BYTES`; `:63` — `leaves_per_segment()` | Honest-holder egress of a challenge fetch: one full segment (`leaves_per_segment() × LEAF_BYTES`) |
| Serving ↔ fetching Tor | `PWD-E9` ([`P2P_2_ENDPOINT_ROUND.md`](P2P_2_ENDPOINT_ROUND.md) §PWD-E9): daemon gets its own tor path, no crossover to the archival-serving persona; launch path takes instance identity as a parameter. Implemented 2026-09-09 (`DaemonTorControl`, `shekyl-tor-control-daemon`) | Closed. Constrains `SF-D2` (RULED): reuse is the **daemon zone's** SOCKS, never the serving persona's |
| Intro-layer PoW | `rust/shekyl-tor-control-wallet/src/onion_service.rs:146–148` — `HiddenServicePoW` defaults **on**; `rust/shekyl-tor-control-client/src/control/onion.rs:272–292` — PoW throttles rendezvous **arrival**, not egress; over onion the body transfer is symmetric (flow control). `control/actor.rs:1725–1754` — live `ADD_ONION` with PoW. Measurement: [`SP_T3_SKELETON_MEASUREMENT.md`](SP_T3_SKELETON_MEASUREMENT.md) SPIKE-F-15/17/18, §19/§19a | Threat-3 pin: intro flooding is priced; not general Tor lore |

## 4. Already closed — do not re-litigate

| Premise | Where |
| --- | --- |
| Test **is** a read; miners are ordinary clients; a distinguishable challenge path is teaching-to-the-test | TJ §9, §9.1 |
| Witness = producer of block *h* | Challenge mechanism fork 2 (ruled 2026-08-10) |
| Daemon is client; wallet is server; no wallet-to-wallet; HTTP-over-onion not a Levin message; RPC a separate layer; fetcher beside `shekyl-daemon-rpc` (process locality, not crate membership) | `EU-D1` |
| **Client crate is `shekyl-p-fetch`.** Counterpart of `shekyl-p-serve`. Codec is `shekyl-curve-tree` (shared, not mirrored). Virt-port home is `shekyl-curve-tree`. Not `shekyl-p-transport` (`PWD-E9`). Dependency cut is a gate owed at implementation (`scripts/ci/check_p_fetch_dep_cut.sh`) | `SF-D4` RULED 2026-09-12 |
| Endpoint = raw 32-byte Ed25519; address is display form; discovery is a chain read at the epoch-open drawable snapshot | `EU-D3`, `EU-D4` |
| Enumerability of onions is a design input; serve-side rate-limit is load-bearing | `EU-D6` |
| `GET /shard/{id}`; identical 404s for every non-servable outcome; only content-type + content-length on the response; hand-rolled HTTP/1.1 | `RF-R1` |
| **Request-header amendment RULED 2026-09-13, not yet landed:** exactly one named header is required and decodes canonically to 40 bytes `nonce[32] ‖ height_le[8]` — fresh random for every request, both callers, plus the published chain-tip height at request time (for the miner building *h*, that is *h*−1). Missing, malformed, duplicate, or wrong-length values are the same identical complete-head 404. All other request headers remain ignored. Exact header spelling and canonical textual encoding land code-plus-tests first under `RF-R1`'s transcription discipline, then the living contract records them in the same implementation PR | `SF-D5` amendment; implementation carrier is the `shekyl-p-serve` + `shekyl-p-fetch` PR |
| **Request unit is a whole shard.** `{id}` is an exact decimal `u64`; no suffix, no query string (`RF-R1` request grammar; `serve.rs:558–560` parses exactly that). There is no leaf addressing. The challenge caller fetches the full segment and extracts leaf ℓ locally — that is the TJ §9 topology working as designed (the honest holder's egress is the cost being measured). `RF-R1`'s reopening clause permits "an additional path that suffixes `/shard/`" if a later request contract is needed; that suffix is exactly where a leaf-addressed challenge fetch would enter, and it is the natural optimization for anyone looking at ~3.33 MB per challenge. **`SF-D1` holds that door shut:** any future suffix path must be usable by both callers, or it is a second path by another name | `RF-R1`; `SF-D1` |
| **Serving and fetching do not share a Tor instance.** `PWD-E9` (RULED 2026-09-08, implemented 2026-09-09): the daemon gets its own tor path with no crossover to the archival-serving persona; the launch path takes instance identity as a parameter, so sharing the code cannot produce a shared instance. The ratified §7 guard residual splits one application's identities; E9 forbids two applications sharing one instance, and the ephemeral/durable asymmetry makes the crossover strictly worse. **`SF-D11` withdrawn** — asked in this round, then closed by reading `PWD-E9` | `PWD-E9` |
| **Fetch outbound reuses the tor zone's existing SOCKS, unconditionally.** No second Tor process. No manufactured SOCKS reopen. The object of reuse is the **zone proxy** (`zone.m_proxy_address` / `socks_connect`), not always `DaemonTorControl` — `--tx-proxy` / `--anonymous-inbound` already yield the managed instance and still leave a tor-zone SOCKS. PWD-E7 is not re-ruled. Shared-instance residual (P2P ↔ archival-fetch on one process) is accepted (§7 threat 4) and is the `SF-D3` ruling, not a leftover | `SF-D2` RULED 2026-09-12 |
| **Unauthenticated SOCKS, no isolation flags.** The fetch client presents no SOCKS credentials and sets no isolation flags on the zone proxy. Circuit assignment is Tor's, per its own defaults — this is not a one-circuit guarantee. Fetches then share circuits with overlay P2P (no credentials on the same SOCKS); that blending is a consequence, not a cover mechanism. Cover is TRC's subject | `SF-D3` RULED 2026-09-12 |
| **The virtual port is 80**, a shared constant both sides read from `shekyl-curve-tree` (`SF-D4` named the home). Today's `SERVING_VIRTUAL_PORT` is `pub(crate)` in `shekyl-engine-core` (`serving/task.rs:52`) — the current location, not the home; the implementation PR moves it. Two `80`s that happen to agree are still not the ratification — this row is the number; the implementation PR puts one constant in `shekyl-curve-tree` and both sides read it. **Request amendment:** same `GET /shard/{id}`, one required header decoding to `nonce[32] ‖ height_le[8]`, no path token, query string, or body; every production call uses it | `SF-D5` RULED 2026-09-12; AMENDED 2026-09-13 |
| **Timeout / miss / retry taxonomy.** One table, two caller columns. Per-attempt handling is the client's (`SF-D1`); the axis is whom the scheduler names next and what exhaustion means. Organic draw bound `k` is the fill scheduler's (`TJ-D`), not the fetch crate's (`client-need` on remaining-empty or `k`). No-endpoint on the bond record is a non-row (filter / pre-dial miss). 404 is a completed exchange (immediate miss), not a retry. `content-length` must equal the constant `signature_envelope_len` plus `framed_len()`; disagreement is malformed and is known after fixed metadata but before segment bytes. Parse, root-mismatch, and bad-countersignature remain typed separately. Reopen if W₂ retry budget and `CHALLENGE_RESPONSE_BLOCKS` cannot coexist | `SF-D6` RULED 2026-09-12; AMENDED 2026-09-13 |
| **One fixed client in-flight cap `N`, one shared admission path, no caller differentiation.** Challenge and organic use the same client code, admission, and request; no priority, reservation, caller tag, or second entry point. The API is `fetch(destination, shard_id, header)` — schedulers name `P`; the HTTP path names only `s`. `N` slots, no unbounded buffer: a scheduler waits for a slot. `N` is also `N × SHARD_BYTES` on the Pi 4 floor (the client materialises the segment to verify `R_k`). Not organic draw cap `k` and not a function of `D`. SP-T3 re-base / W₂ owns the upper bound as min(circuit-churn, memory); the implementation PR owns the lower-bound judgement. Reopen if capped reconstruct throughput falls below TJ-D's chain-growth requirement, or wait-for-a-slot plus transfer approaches `CHALLENGE_RESPONSE_BLOCKS` | `SF-D7` RULED 2026-09-12 |
| **Organic selection is a uniform memoryless draw** over the drawable holder set of shard `s`, performed by the organic scheduler, not by `shekyl-p-fetch`. Per-fetch exclusion is scratch, not memory. The fetch client forms no opinions — it is given a destination | `SF-D10` RULED; `SF-D12` corollary |
| **Countersign with the bond record's hybrid identity key**, `BondPost.hybrid_public_key`, both Ed25519 and ML-DSA legs. This rules the key, not the message (the message is `SF-D8`'s). This is not the onion key and never the cold `bond_spend_pk`. `shekyl-p-serve` holds no key material: `PServeEndpoint` takes a signer callback; tests inject a test key; SH-2 wires the persona secret. The onion endpoint is authenticated by the Tor rendezvous and bound beside the identity key on P's authorized bond record; the response signature proves the live responder also controls P's identity key | `SF-D13` RULED 2026-09-13 |
| **The signed message is `nonce[32] ‖ height_le[8] ‖ shard_id_le[8]`** — requester-random, published tip height, then the `u64` `P` parsed from `/shard/{id}`, under a new versioned domain (the v1 nonce-only domain is not reused). The challenge tuple and `cb_out_key` are not in this message: the fetch proves `P` served, not which miner asked. `shard_id` stops a decoy-route signature being filed as a pass for a different shard. The pass record **carries** the 32-byte random (it cannot be recomputed); admission of a challenge pass checks signed height against the block's predecessor height. Domain string and KAT are pinned by the implementation PR | `SF-D8` message half RULED 2026-09-13; AMENDED 2026-09-13 |
| **Inner frame:** `ServedFrameHeader` (leaf_count ‖ padding_len ‖ segment ‖ padding); codec owned by `shekyl-curve-tree`; write-zero read-anything. `RF-D4` itself carries no countersignature and is unchanged | `RF-D4`, `RF-D7` |
| **Response carrier:** the HTTP body is an outer binary envelope carrying the canonical `HybridSignature` (both legs, fixed length), followed by the unchanged `RF-D4` frame. HTTP response headers stay exactly `content-type` and `content-length`; `content-length` covers envelope plus frame. No signature leg is text-encoded into a header. Verification happens inside the fetch call; the client returns verified-or-refused, never raw bytes | `SF-D8` carrier RULED 2026-09-13 |
| Padding field reserved, no scheme; TJ-H mitigation at the Tor layer (vanguards on the **wallet** serve path) | TJ-H (ruled 2026-08-08) |
| Server bind `127.0.0.1:0`; reachability is `ADD_ONION` | `RF-R1`, `shekyl-p-host` |
| SP-T3's numbers measured persona→persona and must re-base daemon→wallet before promotion | `EU-D1` consequence 4 |

## 5. `SF-D1` — premised at open, not asked

**One client protocol. The challenge fetch and the organic read are both
callers of it.** No third wallet-side client; no challenge-only harness;
no caller-specific header, path token, or isolation shape that would let
`P` distinguish a test from a read. Two production schedulers drive the
same client entry point `fetch(destination, shard_id, header)` — "you
produced block *h*: fetch leaf ℓ of shard *s* from assigned `P`" and
"this daemon needs shard *s*" — and tests are a third scheduler of
that same entry point, not a separate path. The HTTP request names
only the shard; the destination is whom the scheduler named, not a
caller tag on the wire.

Reopen if a storage-only pruned-daemon path is shown to exercise the
serve endpoint end to end without a fetch client. (Also if `EU-D1` or
TJ §9 is itself reopened — those are the substrate this premise sits
on, not a substitute for a local falsifier.)

**Latch on the `RF-R1` suffix door (§4).** A later request contract that
suffixes `/shard/` is a named reopening of `RF-R1`, not of this round —
and it inherits this premise: the new path must be usable by both
callers. A leaf-addressed challenge-only suffix is a second path.

## 6. Round-1 questions — all disposed 2026-09-13

Each question below is recorded with its ruling and a **reopen
criterion**. Rick ruled them. `SF-D2`…`SF-D7` RULED. `SF-D9` done
(same-change heading). `SF-D10` RULED. `SF-D11` withdrawn (§4 /
`PWD-E9`). `SF-D12` a corollary of `SF-D10`, not a coupled question.
`SF-D13` ruled the signing key before `SF-D8`; `SF-D8` RULED last
(signed message, then carrier), which lifted the rule-26 halt.
`SF-D5`/`SF-D8` were amended later the same day: both callers send
requester-random plus published-tip height; the challenge tuple is not
on the fetch.

### `SF-D2` — daemon Tor outbound posture — RULED 2026-09-12

Reuse the tor zone's existing SOCKS, unconditionally. No second Tor
process. No manufactured SOCKS reopen. Unauthenticated SOCKS, no
isolation flags (`SF-D3`).

The round-open premise that `shekyl-tor-control-daemon` exposes no
SOCKS consumer was **false of the implementation** (SUPERSEDED
2026-09-12). SOCKS is discovered (`ephemeral.rs:18` crate-doc; `:240`
`GETINFO net/listeners/socks`) and consumed
(`net_node.inl:878` `zone.m_connect = &socks_connect`; `:879`
`zone.m_proxy_address`). Default posture is inbound onion **plus**
SOCKS outbound on the tor zone. `--tx-proxy` / `--anonymous-inbound`
yield the managed instance (`net_node.inl:815–819`) and still leave a
tor-zone SOCKS.

The object of reuse is the **zone proxy**, not always
`DaemonTorControl`. PWD-E7 is not re-ruled. Serving↔fetching is not
this question (`PWD-E9` / `SF-D11` withdrawn). The residual this
question actually owns is shared-instance correlation of overlay P2P and
archival-fetch on one process (§7 threat 4, named next to `EU-D1` /
SPIKE-F-12). That residual is accepted: guards are per-process.
`SF-D3` does not cut it with credentials or isolation flags, and a
second Tor is a second failure domain and a second version to
supervise on the Pi 4 floor (rule 76). `--no-ephemeral-tor` with no
`--tx-proxy` leaves no tor zone and no SOCKS: refuse-at-construction,
not a second Tor and not a fetch-failure. `SF-D6` names that case as
a non-row so it cannot drift back in as a taxonomy outcome.

- **Reopen if:** the SP-T3 re-base measurement over this topology
  shows the accepted residual is worse than a second Tor process at
  the Pi 4 floor.

### `SF-D3` — SOCKS isolation posture — RULED 2026-09-12

The fetch client opens **unauthenticated SOCKS** to the zone's proxy
and **sets no isolation flags**. Circuit assignment is Tor's, per its
own defaults. Any blending with overlay traffic is a **consequence,
not a cover mechanism** — cover is TRC's subject.

What "no extra isolation" means (and does not). `IsolateSOCKSAuth` is
on by default, but an unauthenticated SOCKS connection has nothing to
isolate on, so streams fall together — which is what overlay P2P does
today (`src/net/socks.cpp:246–271` emits SOCKS5 no-auth when
`userinfo` is empty; `socks_connect_internal` presents none).
`IsolateClientAddr` and `IsolateDestAddr`/`IsolateDestPort` are
separate flags with their own defaults. Destination-based isolation
would split circuits per onion regardless of client credentials. The
daemon spawn does not pass those flags (`--SocksPort` is
`SocksPort::Auto` only, `actor.rs:859`). So the ruling is the
**client contract**: no SOCKS credentials, no isolation flags. It
does **not** guarantee one circuit. An implementer who reads it as a
one-circuit guarantee will write a test asserting that — do not.

Direct consequence, stated rather than inferred. Fetches will then
share circuits with overlay P2P: no credentials on the same SOCKS,
`IsolateSOCKSAuth` has nothing to split on. That is where blending
actually happens, which is why it is a side effect. Cover is TRC's
subject, obtained from relay volume. This row does not claim blending
as a privacy benefit — that argument is TRC's owed measurement. No
protocol carrier is minted; [`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md)
§1.6 is not this client's to trigger.

Contention (so it is not re-derived as a reason to isolate). A
~3.33 MB shard transfer sharing a circuit with P2P contends with
block and transaction propagation on that circuit's window. At any
plausible throughput that is seconds against a 120 s block target
(`SHEKYL_DAA_TARGET_SECONDS`), and nowhere near the 16.7-hour
challenge deadline (`CHALLENGE_RESPONSE_BLOCKS = 500`). Miner-seconds
observation, not a reason to isolate.

The wallet's per-`P` `IsolateSOCKSAuth` (`derive_socks_user`) is a
different job: P↔principal firewall on the **wallet** Tor instance.
Do not copy it onto the daemon fetcher. There is no second identity
on this SOCKS to firewall (`PWD-E9`).

The round-open concern that one SOCKS identity lets a guard see the
fetch set was **false of the mechanism** (SUPERSEDED 2026-09-12). A
guard sees that this IP uses Tor, plus circuit-build timing and
volume. It does not see `.onion` destinations, HTTP paths, or which
fetches are challenges. Assignment is on-chain (`SF-D10`).

`SF-D1`'s "isolation key both callers can compute" is discharged by
there being no key. Minting a caller-shaped SOCKS credential later is
a second path and a reopen of `SF-D1`, not of this contract.

What this closes. `SF-D7`'s in-flight cap loses its isolation-cost
input: no per-fetch circuit build, so circuit-build cost does not
force coarser granularity. The cap is how many concurrent transfers
the client should have outstanding. `SF-D6` cannot be a
distinguishable challenge pattern *via isolation shape*, because
there is no isolation shape. Retry-policy-is-a-property-of-the-client
still stands on its own.

- **Reopen if:** a second identity (principal / wallet traffic) is
  shown to share this daemon SOCKS — that is the wallet firewall
  case, and it is a different process today (`PWD-E9`). Not reopened
  by wanting more blending, by a test that one circuit is shared, or
  by the cover-traffic restoration series.

### `SF-D4` — crate home — RULED 2026-09-12

Dedicated `shekyl-p-fetch`. The client half of the protocol whose
server is `shekyl-p-serve`. `shekyl-shard-fetch` (REJECTED name) named
a job; `shekyl-p-fetch` names the other half of a protocol, and the
symmetry is what makes the crate's boundary self-explaining — an agent
seeing both knows where to look without reading either.

`EU-D1` fixed the side: daemon, Rust, not a wallet, not a JSON-RPC
method. "Beside `shekyl-daemon-rpc`" is process locality (the daemon
image), not crate membership. C++/FFI is a temporary seam; crate home
is the Rust composition. There is no `shekyl-daemon` orchestration
crate to fold into.

**Codec shared, not mirrored.** `shekyl-p-fetch` depends on
`shekyl-curve-tree` for `ServedFrameHeader::read` and
`recompute_segment_r_k`. Neither side owns a private copy of the frame
or the `R_k` recompute. A private copy agrees until it doesn't, and
the disagreement surfaces as a verify failure blamed on `P`.

**Virt-port home.** The ratified port is 80 (`SF-D5`), a constant both
`p-serve` and `p-fetch` read from `shekyl-curve-tree` — already the
shared dependency of both halves; no crate minted to hold a number.
Today's `SERVING_VIRTUAL_PORT` is `pub(crate)` in `shekyl-engine-core`
and is the current location, not the home.

**Dependency cut is a gate, not a sentence.** The implementation PR
owes `scripts/ci/check_p_fetch_dep_cut.sh` (same shape as
`check_debit_auth_single_source.sh`; wired beside it in
`grep-gates.yml`). A sentence that tokio-net / SOCKS must not enter
consensus, chain-store, or RPC decays the first time someone adds a
convenience dependency. Rule 47: the gate first asserts
`rust/shekyl-p-fetch/Cargo.toml` exists. Then:

- `shekyl-p-fetch` depends on `shekyl-curve-tree` (codec not mirrored).
- `shekyl-p-fetch` does not depend on `shekyl-engine-core` (virt-port
  is not pulled across).
- `shekyl-p-fetch` does not depend on `shekyl-p-serve`,
  `shekyl-p-host`, or `shekyl-p-transport`.
- `shekyl-p-serve` does not depend on `shekyl-p-fetch`.
- `shekyl-archival-retention`, `shekyl-chain-store`, and
  `shekyl-daemon-rpc` do not depend on `shekyl-p-fetch` (tokio-net /
  SOCKS must not enter consensus, chain-store, or RPC).

**Not `shekyl-p-transport`.** The name similarity is close enough that
someone will propose consolidating them. The reason not to is
`PWD-E9`: serving and fetching do not share a Tor instance.
`p-transport` is the wallet P↔principal isolation crate on the serving
instance. Fetching is the daemon client on the daemon instance. The
crate names will not make that obvious.

Refused homes (graph, not FFI):

- `shekyl-p-serve` / `shekyl-p-host` — server crates; `RF-D4`; would
  put both ends of `PWD-E9` in one graph.
- `shekyl-engine-core` — wallet.
- `shekyl-daemon-rpc` — JSON-RPC; `EU-D1` consequence 5: fetch is not
  an RPC method.
- `shekyl-archival-retention` — consensus assignment / Merkle verify.
- `shekyl-chain-store` — storage; the fill scheduler *calls* fetch.
- `shekyl-curve-tree` — codec; network I/O stays out.
- `shekyl-shard-source` — GUI fixture seam toward Stage 5
  `ArchivalEngine`; wrong side.
- A module of a future `shekyl-daemon` — that crate does not exist.

- **Reopen if:** at implementation, the client turns out to be a thin
  wrapper with no independent dependency set worth cutting — then
  folding into a `shekyl-daemon` orchestration crate's capability bag
  (when that crate exists) is a doc-comment decision, re-ruled at that
  PR's pre-flight. Not a reopen into `shekyl-daemon-rpc` or
  `shekyl-p-serve`. `SF-D1` guarantees two callers, so caller-count is
  not a fold criterion.

### `SF-D5` — dial grammar — RULED 2026-09-12; AMENDED 2026-09-13

Reconstruct the v3 onion address from the 32-byte Ed25519 key
(`EU-D3`: the address is display form; the key is the record). SOCKS
CONNECT through the zone proxy that `SF-D2` reuses, to `onion:80`,
then the `RF-R1` GET. Unauthenticated SOCKS, no isolation flags
(`SF-D3`). No caller-specific path token (`SF-D1`), no query string,
and no request body.

**Request-header amendment (RULED 2026-09-13; AMENDED later the same
day).** Every request carries exactly one named header whose one
canonical textual encoding decodes to exactly 40 bytes:
`nonce[32] ‖ height_le[8]`. Both callers, every request:

- `nonce` is fresh cryptographically random 32 bytes. No two requests
  reuse it. It is **not** `attestation_nonce`. The challenge tuple
  (`block_hash(h−1)`, `cb_out_key`, `P`, `s`, `E`) does not go on the
  fetch — that hash names the assignment, and putting it on the wire
  lets `P` serve the witness and refuse everyone else.
- `height` is the published chain-tip height at request time, as a
  little-endian `u64`. Both `P` and any requester can compute it.
  For the miner building block *h* it is *h*−1. It is freshness, not
  identity: it does not name the assignment.

`P` treats the decoded 40 bytes as opaque input to `SF-D8`'s
response-binding transcript. It does not infer which caller this is.

This rules the **carrier**, not the signed message. The request parser
hands `(nonce, height, shard_id)` to the response-binding seam; `SF-D8`
fixes the signed transcript as
`nonce[32] ‖ height_le[8] ‖ shard_id_le[8]`.

The header's **presence and shape** are ruled here. Its exact spelling
and canonical textual encoding follow `RF-R1`'s transcription
discipline: the implementation PR pins them in code plus tests, adds a
request-side sibling of `RESPONSE_HEADER_NAMES`, and updates
[`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md) in the same
change. This is a concrete carrier, not permission for more fields.
Missing, duplicate, malformed, or wrong-length values are a
complete-head miss and render the same byte-identical 404 as every
other non-servable outcome. All other request headers remain ignored.

**The only semantic request fields.** The 40-byte header is the only
recognized caller-supplied field other than the selected shard id.
Both production callers use one serializer and vary only
`(shard_id, nonce, height)`. Height is the published tip, so at any
moment both callers send the same height distribution. This is the
enforceable `SF-D1` property: ignored HTTP syntax remains
client-controlled on the wire under `RF-R1` (including currently
accepted version-token values and leading-zero ids), so this ruling
does not falsely claim every raw request byte is fixed. It claims the
production client has no second semantic degree of freedom with which
to mark a challenge.

The virtual port is **80**. Conventional HTTP virt-port; carries no
fingerprint beyond the route itself; every existing test and the serve
task already speak it. A non-default port would be a per-operator
distinguisher on an address whose purpose is to be indistinguishable.

**Shape (ruled with this number):** one shared constant both sides
read, not two `80`s that happen to agree. **Home:** `shekyl-curve-tree`
(`SF-D4`). Today's `pub(crate)` in `shekyl-engine-core` is the current
location; the implementation PR moves the declaration. `SF-D4` forbids
the client pulling engine-core to get it.

- **Reopen if:** the Tor layer surfaces a reason a non-default virt
  port cuts an enumeration or scanning class `EU-D6` cares about; or
  the implementation cannot express one canonical 40-byte
  `nonce ‖ height` representation without adding a second request
  field.

### `SF-D6` — timeout / miss / retry taxonomy — RULED 2026-09-12; AMENDED 2026-09-13

The consensus deadline exists (`CHALLENGE_RESPONSE_BLOCKS = 500`) and
binds the **challenge** caller only. The organic caller has no
deadline. W₂ is **not** this round's to pin — it is a measurement over
**this** topology, owed by the SP-T3 re-base. This round specifies
*shape*.

Per-attempt handling is a property of the client (`SF-D1`), identical
for both callers. Isolation cannot distinguish them (`SF-D3`). The
only axis that may differ is **whom the scheduler names next**, and
**what exhaustion means**.

**Non-rows (this table never sees them).** They fail before a dial.
Organic never names that `P`. Challenge already has its `P` from the
assignment; a non-row there is a pre-dial miss or a construction
refusal, not a retry of an address the witness never had.

- **No zone proxy** (`SF-D2` handoff): `--no-ephemeral-tor` and no
  `--tx-proxy` leaves no tor-zone SOCKS. The SOCKS client refuses at
  construction. Not a fetch failure and not a second Tor.
- **Missing local `FrozenSegmentRecord` / `R_k`.** Same *behaviour*
  (do not dial) on both callers; **two reasons, two errors — do not
  wire one `witness-local` predicate.** Challenge: the producer of
  block *h* cannot answer the assignment without the record; that
  fetch is refused at construction, not a `P` miss. Organic: the
  daemon wants shard `s` and lacks the record that would let it
  verify `s` — a **chain-state gap**. Whether the fill scheduler
  should have asked for `s` at all in that state is reconstruct /
  TJ-D, not this table. The fetch client still does not dial.
- **No endpoint on the bond record** (endpoint was *not* on the
  record). Chain-state, knowable before any dial — same shape as
  missing `FrozenSegmentRecord`. Split of the stall-class row: that
  row is SOCKS CONNECT / intro failure when the endpoint *was* on
  the record. Organic: filter out of the draw set (do not spend a
  dial discovering it). Challenge: pre-dial check on the assigned
  `P`; no endpoint is an immediate **miss**, not bounded retries
  against an address the witness never had. Do not collapse those
  two under "unpublished onion."

  This is the only miss that costs `P` a slash contribution for a
  **chain-state** condition rather than a behavioural one. `P`
  published no endpoint, which under `EU-D1` is `P`'s own omission —
  the verdict is defensible. The drawable snapshot and the endpoint
  move together at epoch open (`EU-D4`): the witness reads the
  endpoint from the same snapshot that named the assignment, so "no
  endpoint at assignment time" is a stable fact for the whole
  window, not a race. An `EndpointUpdate` that has not landed in
  this epoch's snapshot, or a record whose endpoint was never set
  at `JoinMarket`, therefore produces misses for every assignment
  in the interval. The operator-facing half belongs to `EU-D1`: a
  bonded persona with no published endpoint is in a slash-accruing
  state and should know it. Not this round's to fix; this round is
  where the fetch taxonomy makes it true.

**Length.** `ServedFrameHeader::framed_len()` declares the **inner
frame** (header + `leaf_count × LEAF_BYTES` + `padding_len`), never
frozen `SHARD_BYTES = 3,326,976` as the whole HTTP body size. That
constant is the **segment**. `SF-D8` (RULED) puts a returned-signature
envelope outside that frame, so the HTTP `content-length` must equal
`signature_envelope_len + framed_len()`, where `signature_envelope_len`
is the fixed canonical `HybridSignature` length — a constant, not a
decoded field. Treating `framed_len()` alone
as the HTTP body length is SUPERSEDED 2026-09-13 by the countersigned
response requirement.

`padding_len` lives *inside* the declared frame length, so a padded
response is still well-formed and **TJ-H never produces a
length-taxonomy row**. That placement is also what removes the benign
explanation for overlength: without it, extra bytes would be
ambiguous between a padding variant and a fault.

HTTP `content-length` and the decoded outer-envelope-plus-frame length
**must agree**. Disagreement is malformed, not truncation. Detection
occurs after the fixed response metadata (signature envelope and
`ServedFrameHeader`) has arrived but **before segment or padding
bytes** — not before any HTTP body byte, as the pre-countersignature
text incorrectly claimed. It is still an immediate miss: a hostile
`P` cannot make the client consume a shard body before discovering
the disagreement. Truncation is: they agreed on `N`, and fewer than
`N` total body bytes arrived. Overlength is: they agreed on `N`, and
more than `N` total body bytes arrived.

**Short is indistinguishable.** A dead circuit and a `P` that
declares `framed_len()` then stops short produce the same client
observation. The row is not split: guessing which one it was would
hand `P` a way to choose the verdict. Stall-class on the organic
side excludes-and-redraws, which is correct either way. On the
challenge side it means bounded retries of **that** `P` inside the
deadline — and retrying a `P` that is deliberately truncating spends
the deadline on an outcome that will not change.

**404 is a response, not transport.** `RF-R1` makes every non-servable
outcome one identical 404, so the client cannot tell never-held from
dropped from refusing — that is the reason **not to distinguish**.
The reason **not to retry** the assigned `P` is separate: a clean
404 is a completed HTTP exchange in which `P` answered and the
answer was "no." Truncation can be a dead circuit; a 404 cannot.
Challenge: immediate **miss**. Organic: exclude, draw next (a
different `P` may hold `s`).

**W₂ measurement input (not a taxonomy change).** The challenge-side
bounded-retry budget (timeout / stall / truncation / intro failure,
against the assigned `P`) must be small enough that a truncating
`P` cannot consume `CHALLENGE_RESPONSE_BLOCKS`. The W₂ re-base will
not surface this on its own: a truncating `P` looks like weather.
The number the measurement produces has to satisfy this requirement.

**Organic exclusion**, once, for every "exclude" below: `SF-D10`
scratch on the organic scheduler — without replacement inside this
need, dies with the need. No longer-lived list. The challenge
caller does not consult this; assignment is the selection, and
stall-class retries are of **that** `P`.

**Organic draw bound, owed.** `D` is unbounded and growing (challenge
mechanism §9.6 item 3). "Exclude, draw next" until the set is empty
is a full walk of `D` for a shard nobody currently serves — a
circuit dial per holder, with no deadline forcing a stop. That walk
is **not** implied. Either the draw is capped at some `k` (try `k`,
then `client-need` with holders remaining) or "exhausted" means
something other than "all `D`". **`k` is `TJ-D`'s** — the fill
scheduler that names the next `P`. This table specifies the walk;
this round does not pick `k` and the fetch crate does not pin it.
Distinct from `SF-D7`: that cap is concurrent transfers, not how
many holders one organic need tries.

**`client-need`** is the organic terminal: this fetch stopped without
a verified body, because the remaining draw set was empty **or**
the owed draw cap `k` was hit. What the fill scheduler does with
that — backoff and retry the whole fetch later, give up on `s` for
this pass, operator surface — is `TJ-D`'s. This table does not pick
an implementation.

| Outcome | Challenge (assigned `P`) | Organic (`SF-D10` draw) |
| --- | --- | --- |
| Circuit timeout / HTTP stall / SOCKS CONNECT or intro failure (endpoint *was* on the record) | Stall-class: bounded retries of **that** `P` inside the deadline, then **miss** | Stall-class: same per-attempt retries; then exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Body short of agreed `N` (truncated transfer) | Stall-class | Stall-class |
| Body long of agreed `N` (overlength) | Malformed → **miss** | Malformed: exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| `content-length` ≠ `signature_envelope_len + framed_len()` (envelope length is a constant; known after the frame header, before segment bytes) | Malformed → **miss** | Malformed: exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Identical 404 (`RF-R1`) | **Miss.** Completed exchange; `P` answered "no." Do not retry **that** `P`. Identical 404s are why the client must not distinguish *which* "no" | Exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Malformed response envelope / frame | Malformed → **miss**. Logged (`SF-D12`); not a selection input | Malformed: log; exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| `R_k` mismatch | Root-mismatch → **miss**. Typed and logged (`SF-D8`, `SF-D12`); not a selection input | Root-mismatch: log; exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Countersignature invalid for `SF-D8`'s ruled `nonce ‖ height ‖ shard_id` transcript under P's bond-record hybrid identity key | Bad-countersignature → **miss**. Typed and logged (`SF-D8`, `SF-D12`); completed response, so no retry of that `P` | Bad-countersignature: log; exclude, draw next. Cap/`k` or remaining-empty → **client-need** |

- **Amendment 2026-09-13:** the last three rows split parse failure,
  `R_k` mismatch, and bad countersignature into distinct verdicts.
  Their scheduler consequence is intentionally the same; their typed
  errors are not.
- **Constraint:** retries must not become a distinguishable challenge
  pattern — the retry policy is a property of the client, not of the
  caller. Isolation shape is no longer a way to violate that:
  `SF-D3` RULED there is none (D3 dependency discharged on this
  axis; the constraint still stands on its own).
- **Reopen if:** the W₂ re-base shows the retry budget and the
  consensus deadline cannot coexist. No host qualifier — the challenge
  caller is a miner (producer of block *h*); the Pi 4 floor is a
  validation commitment and essentially never runs this caller. The
  organic caller has no deadline, so nothing about a floor binds it
  either. The truncating-`P` budget bound above is an *input* to that
  measurement, not a second reopen.

### `SF-D7` — concurrency vs growing `D` — RULED 2026-09-12

Server-side `MAX_INFLIGHT` / `max_streams` remain SPIKE-PIN-1/2 (the W₂
rig's). The client needs its own in-flight bound, sized for **both**
callers sharing one daemon Tor instance. Distinct from `SF-D6`'s organic draw cap `k` (the fill scheduler's):
that is how many holders one organic need tries; this is how many
transfers may be outstanding at once.

Challenge mechanism §9.6 item 3 stands: `D` is unbounded. This cap is
**not** a function of `D`. Coverage math at maturity counts
*assignments across the network*; it does not count transfers one
client has outstanding. A challenge fetch is one shard against
`CHALLENGE_RESPONSE_BLOCKS` (~16.7 h). The challenge caller's organic
load is its own chain-store fill, not a function of `D`.

`SF-D3` discharged the isolation-cost input. The lean had hedged on
circuit-build cost forcing coarser granularity; with no per-fetch
circuit build there is no such cost. The cap is purely how many
concurrent transfers the client should have outstanding.

**Two shapes, one cap.** A miner reads speculatively while building on
*h*; if it wins *h*+1 it carries the attestations. Challenge fetches
therefore arrive in a burst tied to block arrival
(`SHEKYL_DAA_TARGET_SECONDS` = 120), and they are latency-insensitive
individually (hours of deadline). Organic reconstruct is a sustained
fill with no deadline at all. Sharing a cap, the caller a small cap
would hurt is the deadline-free one.

**No caller differentiation.** Challenge and organic requests enter
the same client code, the same in-flight limiter, and the same
admission path.
There is no priority, reservation, caller tag, second entry point, or
per-caller admission rule. `SF-D1` governs the whole request
mechanism, not only the HTTP bytes: serving `P` must have no way to
distinguish a challenge from an organic request because they are the
same request. Priority was proposed and withdrawn: it is invisible
per request but visible in aggregate. A `P` correlating arrival timing
against block arrival across many fetches could statistically recover
the split — `SF-D10`'s selection-statistics channel reintroduced
through queue order — for a latency benefit the timing analysis shows
is unnecessary.

**Rule 76 is the sizing, not a compromise.** Provision at the floor so
a Pi 4 organic caller is not overcommitted — that is the caller that
actually runs there. A miner is not constrained by a cap sized for a
Pi: its binding constraint is uplink and Tor circuit throughput, not
its ability to track a handful of outstanding transfers. A
floor-derived number is adequate for both, for different reasons.

**The client materialises the segment.** `recompute_segment_r_k`
takes `&[[u8; 128]]`. `SF-D8` returns verified-or-refused, so the
in-flight body is resident until verify finishes. The server streams
chunks so `MAX_INFLIGHT` is not `N × 3.33 MB` on the serve side; the
client cannot. `N` is therefore also a memory cap:
`N × SHARD_BYTES` must fit the Pi 4 floor. Copying the server's
placeholder 64 is 213 MB resident and is refused for the same reason
the server refused to materialise. The SP-T3 / W₂ upper bound is the
**min** of circuit-churn and this memory cap.

**No unbounded buffer.** "Shared queue" is one admission path, not a
list of thousands of pending shards. There are `N` in-flight slots.
A scheduler that wants another transfer waits for a slot. Organic
fill of many shards is the scheduler's loop, back-pressured by `N`,
not an internal queue the challenge caller sits behind.

**The integer is unpinned.** This round rules the *shape* (one fixed
`N`, one shared admission path, `fetch(destination, shard_id, header)`
for both callers). Caller-blind is the HTTP request, not the API:
the path is `/shard/{id}`; the scheduler supplies the destination.
"Small fixed" is not a number. The range: bounded above by the **min** of (what a Pi 4's Tor client
handles without circuit churn — SP-T3 re-base / W₂ over this topology)
and (`N × SHARD_BYTES` on that same floor); bounded below by enough
parallelism that reconstruct is not serialised one shard at a time.
The lower endpoint is the implementation PR's own judgement: that PR
records why its chosen parallelism is acceptable for fill throughput;
it is not a second SP-T3 measurement. The implementation PR pins the
integer from that range. Not a function of `D`.

- **Lean:** one fixed in-flight cap `N`, one shared admission path, and
  the same `fetch(destination, shard_id, header)` for challenge and
  organic requests. No priority or reservation. Concurrent transfers,
  not `k`, not circuit-build cost, not a per-`D` scaling constant.
  Integer unpinned — range above; implementation PR pins it from the
  SP-T3 re-base's upper bound and owns the lower-bound throughput
  judgement.
- **Reopen if:** reconstruct throughput at the cap falls below what
  TJ-D's fill scheduler requires to keep pace with chain growth; or
  wait-for-a-slot plus transfer for a challenge request approaches
  `CHALLENGE_RESPONSE_BLOCKS`. Not reopened by coverage math at
  maturity — that quantity cannot answer this question.

### `SF-D13` — countersigning key — RULED 2026-09-13

The countersignature uses P's stable **hybrid identity key** from the
bond record (`shekyl_wire::BondPost.hybrid_public_key`), both Ed25519
and ML-DSA legs. This ruling does not invent a second key field.
The verifier first binds the public key to `p_canonical_id`, then
verifies the two legs.

**Injection, not custody.** `shekyl-p-serve` remains transport: it
holds no key material. `PServeEndpoint` takes a signer callback that
returns the canonical `HybridSignature` over the `SF-D8` transcript.
Loopback tests inject a test key. Production composition
(`shekyl-p-host` / SH-2) passes the persona hybrid signing secret.
The fetch implementation PR lands the callback and the envelope;
SH-2 wires the live secret. The unsigned HTTP half is not a
substitute for a countersigned loopback test.

This ruling selects the **key only**. It does not inherit
`verify_pass_countersignature`'s current nonce-only message from
`shekyl-archival-retention/src/attestation_wire.rs`: caller-supplied
opaque nonces invalidate that function's premise that a nonce
containing `shard_id` is by itself a server-enforced shard binding.
`SF-D8` rules the signed transcript
(`nonce ‖ height ‖ shard_id`).

Two same-neighbourhood keys are expressly **not** selected:

- not the raw onion endpoint key as the Ed25519 leg; the onion key
  authenticates the Tor rendezvous and may rotate through
  `EndpointUpdate`, while `p_canonical_id` remains the hash of the
  stable canonical hybrid identity key;
- never `bond_spend_pk`, the cold debit authorizer that does not cross
  into the serving tree.

No sibling proof-of-possession field is added to the bond wire. The
authorized bond record binds the endpoint key beside P's hybrid
identity key; the Tor rendezvous proves control of the endpoint key;
the countersigned response proves that the live responder also
controls P's hybrid identity key. Online cooperation remains the
already-accepted fully-collusive case; an additional static proof does
not remove it.

- **Reopen if:** grounding the `JoinMarket` / `EndpointUpdate`
  authorization preimage shows the endpoint bytes are not covered by
  the record's authorization; or Tor v3 rendezvous is shown not to
  authenticate the raw endpoint key the drawable snapshot carries.
  Re-evaluation is a format round over the bond binding, not an
  opportunistic key swap in `shekyl-p-serve`.

### `SF-D8` — returned signature and verify seam — RULED 2026-09-13

The original `R_k`-only lean was incomplete. The fetcher's output is a
**typed result both callers consume**, produced only after all three
checks:

1. parse the returned response envelope and inner frame
   (`ServedFrameHeader::read`);
2. recompute `R_k` (`recompute_segment_r_k`) and compare it with the
   daemon's local `FrozenSegmentRecord`;
3. verify P's hybrid countersignature under `SF-D13` against the ruled
   transcript `nonce[32] ‖ height_le[8] ‖ shard_id_le[8]` — the 40-byte
   header this request sent, followed by the `u64` this request asked
   for.

No store handle exists at verify time (TJ-F liveness). The two
verification refusals are distinct typed errors — `RootMismatch` and
`BadCountersignature`; response-envelope/frame decode remains its own
parse error rather than being folded into either. `SF-D6` gives all
three the same scheduler consequence while preserving the diagnostic
distinction.

The successful type retains the countersignature beside the verified
shard. The witness caller keeps it for pass-record construction; the
organic caller discards it after verification. Both receive the same
type from the same call. Pass-record construction itself is **out of
scope** — the type this round names is the input that round consumes.
Reconstruct's "install these leaves" is also out of scope (TJ-D
storage); it consumes the same typed result.

**Request side is closed.** `SF-D5` carries the 40-byte header: same
`GET /shard/{id}`, one required canonical `nonce[32] ‖ height_le[8]`,
no path token, query string, or body. Both callers generate a fresh
random `nonce` and attach the published tip height. `P` parses `{id}`
and constructs the signed transcript from the header plus that id.

**The fetch proves `P` served, not which miner asked.** Binding
`cb_out_key` or the rest of the challenge tuple into the request
would name the assignment on the wire. Same-height reuse of a
signature across competing blocks is accepted: Alice fetched, `P`
served, Bob's winning block may carry that evidence. The 2-of-3
counts whether `P` served, not who asked.

**Grounding finding — a signature that does not cover the parsed
route id is a confused deputy.** The caller chooses the random
bytes, so signing them alone (or them plus height) does not bind the
signature to `/shard/{id}`: a dishonest witness can request a held
decoy while filing the signature as a pass for an unheld target.
Appending the server-parsed shard id makes that signature fail for
`target`. This is not additional evidence against a fully collusive
P+witness; that residual remains priced by the ruled 2-of-3 quadratic.

**Signed message — RULED 2026-09-13; AMENDED later the same day.**
`P` signs one fixed, domain-separated encoding of
`nonce[32] ‖ height_le[8] ‖ shard_id_le[8]`, where `nonce` and
`height` are the decoded header values exactly as received and
`shard_id` is the exact `u64` `P` parsed from this request's
`/shard/{id}`. Both signature legs cover that message. The fetch
client reconstructs it from the header it sent and the shard id it
requested; it never reads those values back from the response.

The pass record **carries** the 32-byte `nonce` — it is requester-
random, so it cannot be recomputed from chain terms. That reverses
the credit-wire line that the nonce is not stored. Admission of a
challenge pass reconstructs the message as
`carried_nonce ‖ predecessor_height_le ‖ record.shard_id` and checks
the signature; signed height must equal the block's predecessor
height (the published tip while building *h*). Height itself is not
an extra stored field.

The message gets a **new versioned domain string**; the signature
API's v1 nonce-only domain is not reused, so a v1 signature can
never verify as a v2 one. The domain string, the helper home, and a
KAT are pinned by the implementation PR. Landing this requires an
explicit amendment to the nonce-only response-format contract, to
`verify_pass_countersignature`, and to the pass-record layout that
today omits the nonce; the implementation PR makes those amendments,
it does not override them silently.

**Response carrier — RULED 2026-09-13.** `RF-D4`'s
`ServedFrameHeader` contains only `leaf_count` and `padding_len` and
the landed HTTP response carries no countersignature, so the signature
needs a home that is neither the inner frame nor a header:

- **Carrier:** the HTTP body is an outer binary response envelope
  carrying the canonical `HybridSignature` (both legs, the fixed
  canonical length from `shekyl-crypto-pq`), followed by the existing
  `ServedFrameHeader` and segment bytes. The HTTP response headers stay
  exactly `content-type` and `content-length`; no signature leg is
  text-encoded into a header — a 3,309-byte ML-DSA leg does not belong
  in one. The inner `RF-D4` frame is byte-for-byte unchanged, and
  `content-length` covers envelope plus frame (this is the
  `signature_envelope_len + framed_len()` equality `SF-D6` already
  checks). Because the signature length is fixed, the envelope adds no
  length field and the frame offset is a constant. The serve crate
  obtains the signature from the `SF-D13` callback; it does not load
  the secret.
- **Verify placement:** inside the fetch call. The client returns only
  verified-or-refused, never raw bytes — a raw-bytes return invites a
  caller to skip either check. The successful type carries the
  verified shard and the signature; parse, `RootMismatch`, and
  `BadCountersignature` are its three typed refusals.
- **Reopen if:** the reconstruct caller demonstrates a need for an
  unverified stream (for example partial-segment resume) that cannot
  be met behind the seam; or the canonical hybrid-signature encoding
  cannot be parsed incrementally within the rule-76 memory bound.

Whether a verify failure is remembered is `SF-D12`: it is not a
selection input. It is logged (`SF-D12`).

### `SF-D9` — `RF-R1` heading correction

Not a protocol decision. Same-change doc task (rule 91): retitle the
living contract ([`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md))
as daemon→P HTTP-over-onion, cite `EU-D1`, leave the byte rules —
path, status/headers, request grammar, transport, falsifier —
untouched. **Done in this change.** The heading the contract carried
before `EU-D1` ruled the client side is this section and the SHA of
[PR #714](https://github.com/Shekyl-Foundation/shekyl-core/pull/714),
not a parenthetical in the living contract.

### `SF-D10` — organic selection — RULED 2026-09-12

Uniform memoryless draw over the holder set of shard `s`, read from the
drawable snapshot, performed by the **organic scheduler**. Per-need
exclusion permitted. No persistent state. `shekyl-p-fetch` does not
draw; it is given a destination.

The challenge caller does not consult this rule. The assignment is the
selection. `P` already has that assignment from the chain (§3 derived
assignment): it computes its own window the moment the block lands. A
client-side fence around organic-demand calibration was a fence around
an open gate.

Three pins so "memoryless" is not underspecified:

1. **Distribution.** Uniform over the drawable holders of `s`. Uniform
   is the only stateless distribution with no bias, and it spreads any
   single daemon's need profile thinly across the set rather than
   concentrating it on one persona.
2. **Per-need exclusion is not memory.** Within one organic need's
   retry sequence, draw without replacement — do not immediately
   re-dial the `P` that just timed out. Scratch state that dies with
   the need. No persistence, no reorg interaction, no cross-daemon
   divergence, nothing exploitable, and it saves the wasted circuit
   standup a strictly with-replacement draw would sometimes spend.
   Strict re-draw-with-replacement is wasteful; a persistent exclusion
   list is the thing this ruling refuses.
3. **The fetch client forms no opinions.** Tor does not lack
   measurement — it has bandwidth authorities. What it lacks is
   client-side reputation. Measurement lives at the consensus layer;
   clients consume it without forming private opinions. Same
   architecture: the challenge system is the measurement authority;
   the organic scheduler consumes the drawable snapshot and draws;
   `shekyl-p-fetch` dials whom it is given. Private per-client
   reputation diverges, cannot be audited, and is shapeable by whoever
   wants to be excluded. A privileged-`P` system is an attack surface.

A timeout over Tor carries almost no information about `P`; the base
failure rate swamps the signal. Memory keyed on that is a memory of
noise, and it costs a persistence surface, a reorg interaction, and
cross-daemon divergence to store it. After an `SF-D6` failure the next
try is another `P`, which is another complete circuit standup, with
the same 1/`X` network failure plus whatever is at `P`.

The residual that looked like a selection problem — `P` knows it is in
a window, so it can serve during windows and refuse outside them — is
availability-level teaching-to-the-test. What defeats it is window
density: whether assignments are frequent enough that windows overlap
into approximately always. That is the challenge mechanism's coverage
math as a function of `D` (settled exhaustive-coverage doctrine: every
bonded pair challenged every epoch; §9.6 item 3: load `λ·D/E` rises
with `D`). It is not a client-side selection question. `SF-D10` does
not inherit it.

- **Reopen if:** the drawable snapshot is shown not to be the holder
  set the organic caller should read (a later-bonded holder of `s`
  that is not in the epoch-open snapshot is the correct draw set); or
  a consensus-layer measurement of `P` availability exists that
  clients can consume without forming private opinions (the
  bandwidth-authority analogue); or a timeout over onion is shown to
  carry usable information about `P` (the base failure rate no longer
  swamps the signal).

### `SF-D11` — serving ↔ fetching Tor instance — WITHDRAWN 2026-09-12

Asked in this round, then closed by reading `PWD-E9` (RULED 2026-09-08,
implemented 2026-09-09). Never an open question of this round; it was
never on the (now-lifted) halt list.
See §4. Identifier kept so grep finds the withdrawal; `SF-D12` is not
renumbered (already published).

### `SF-D12` — verify-failure observability — COROLLARY of `SF-D10` (RULED 2026-09-12)

No persistent memory. An `R_k` mismatch is not a selection input — the
`SF-D6` taxonomy row plus per-fetch exclusion is the entire behavioral
response. It is an observability signal: logged and alarmable on a
pattern, so an operator can notice a persona serving garbage even
though the client acts on it exactly like a timeout. An `R_k` mismatch
is not noisy the way a timeout is — `P` returned bytes that failed
verification against local chain state, which is corruption or malice,
not network weather — and that is why the operator surface keeps the
distinction the mechanism deliberately ignores.

- **Reopen if:** the operator surface is shown to need the client to
  *act* differently on an `R_k` mismatch than on a timeout (a
  mechanism-side distinction), rather than a log distinction. That
  reopens `SF-D10`'s "never a selection input" with it.

## 7. Threat-model frame (rule 26 A3)

Named attacker objectives this round's rulings are evaluated against:

1. **`P` teaching-to-the-test.** Any client behavior that distinguishes
   a challenge fetch from an organic read — a second path, a
   caller-shaped header or path token, a challenge-shaped isolation
   key, a caller-correlated retry pattern, a nonce that equals the
   publicly computable `attestation_nonce` — lets `P` serve the test and
   refuse the job. This is TJ §9's attack, now applied to the client's
   observable surface. `SF-D5`/`SF-D8` close the nonce channel: both
   callers send requester-random plus the published tip height.
   **Client-side selection statistics are not a channel this round
   owns.** Assignment is on-chain; `P` computes its window from the
   chain (`SF-D10`). The residual — serve during windows, refuse
   outside them — is availability-level teaching-to-the-test, defeated
   by window density as a function of `D`. That lives on the challenge
   mechanism (settled exhaustive-coverage doctrine; §9.6 item 3), not
   on organic selection. Verify-failure never steers the draw
   (`SF-D12`); it is logged.
2. **Guard sees the fetch set — SUPERSEDED 2026-09-12 (`SF-D3`).**
   An entry guard does not see onion destinations, HTTP paths, or the
   challenge schedule (on-chain). The client presents no SOCKS
   credentials and sets no isolation flags; circuit assignment is
   Tor's. Sharing circuits with overlay P2P is a consequence of that
   contract, not a leak isolation would cut. See `SF-D3`.
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
   own a re-pin. `SF-D6` owns the client's retry shape and `SF-D7`
   owns its caller-blind admission/`N` so neither adds distinguishable
   load; they do not own the slash.
4. **Shared-instance P2P + archival (accepted, `SF-D2`/`SF-D3`).**
   Overlay P2P and archival fetches share the daemon's Tor instance
   and therefore its entry guards. Fetches then share circuits with
   overlay P2P (no credentials on the same SOCKS) — a consequence, not
   a one-circuit guarantee. A guard-level observer sees Tor use, not
   fetch interest. Accepted-by-construction on one process (guards are
   per-process). Serving↔fetching (persona ↔ principal) is closed by
   `PWD-E9` (`SF-D11` withdrawn). Blending with overlay volume is a
   side effect, not a cover mechanism — cover is TRC's subject.

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
  `PersonaServingHost` and passing the persona hybrid signing secret
  into the `SF-D13` callback) — a named blocker for *production*
  countersignature and for end-to-end onion integration. Loopback
  tests of the envelope inject a test key; they do not wait on SH-2.
  Loopback of the unsigned HTTP half is not that test.
- The endpoint field on the vin (EU's B+C1 slice).
- Availability-level teaching-to-the-test (serve during windows,
  refuse outside them). Coverage math as a function of `D` on
  [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md)
  (settled exhaustive-coverage doctrine; §9.6 item 3: load `λ·D/E`
  rises with `D`). `SF-D10` does not inherit it.

## 9. What "ruled" looks like after Round 1

A living contract the first **client** is written against: crate
`shekyl-p-fetch` (`SF-D4` RULED: counterpart of `shekyl-p-serve`;
codec `shekyl-curve-tree`, shared not mirrored; virt-port home
`shekyl-curve-tree`; dep-cut gate owed at implementation; not
`shekyl-p-transport`),
daemon Tor posture (`SF-D2` RULED: reuse the tor zone's SOCKS;
`SF-D3` RULED: unauthenticated SOCKS, no isolation flags; circuit
assignment is Tor's; blending with overlay is a consequence, not a
cover mechanism — cover is TRC's subject; serving↔fetching already
`PWD-E9`),
dial grammar (key → onion:80, the
port a shared constant both sides read from `shekyl-curve-tree`,
`GET /shard/{id}` plus one required header decoding to
`nonce[32] ‖ height_le[8]` — requester-random and published-tip
height, both callers; `SF-D5` RULED and amended),
one failure taxonomy with two caller columns (`SF-D6` RULED: per-attempt
handling is the client's; 404 is a completed exchange; no-endpoint is a
non-row; organic draw bound `k` is `TJ-D`'s; `content-length` equals the
constant signature-envelope length plus inner `framed_len()`, with
disagreement known before segment bytes; parse, root mismatch, and bad
countersignature are typed separately), one fixed client
in-flight cap and one shared admission path (`SF-D7` RULED:
`fetch(destination, shard_id, header)`; integer pinned by the
implementation PR from SP-T3's upper bound and its own lower-bound
throughput judgement), the stable bond-record hybrid
identity signing key (`SF-D13`: callback into `PServeEndpoint`; crate
holds no secret), the signed message
`nonce[32] ‖ height_le[8] ‖ shard_id_le[8]` under a new versioned
domain (challenge tuple not in the fetch; pass record carries the
random), the outer
fixed-length signature envelope ahead of the unchanged `RF-D4` frame,
and the verified-or-refused typed fetch result (`SF-D8` RULED), and
one organic
selection rule, on the scheduler not the fetch crate: uniform
memoryless draw over the drawable holders of `s`, per-need exclusion
permitted, no persistent state (`SF-D10`); verify-failure is
observability, never a selection input (`SF-D12`).
The challenge is a scheduler of that client. The W₂ measurement plan
is named as Round 0 / pre-flight of the *implementation* PR, over
daemon→wallet — never as a second protocol round. The first
implementation is the client; the first tests are that client against
`shekyl-p-serve`; the challenge caller is wired to the same entry
point.
