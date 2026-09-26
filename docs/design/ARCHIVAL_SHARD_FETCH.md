# Archival shard fetch — the daemon client (design round)

**Status: RULED — Round 1 CLOSED 2026-09-13; implementation in
progress: (a0) LANDED 2026-09-13 (#734); (a)+(b) BUILT 2026-09-13 as
one stacked PR on #734 (sub-PR 1 of the FOLLOWUPS row; §9.1
amendment); (c) LANDED 2026-09-16 — `N = 8` pinned (PR #746).**
Round 1 opened 2026-09-12, grounded `dev@ba4b3c73a`. Every `SF-D`
question is disposed: `SF-D2`, `SF-D3`, `SF-D4`, `SF-D6`, `SF-D7`,
`SF-D10`, `SF-D13` RULED; `SF-D5` RULED and amended with the request
carrier; `SF-D8` RULED (signed message and response carrier); `SF-D9`
done; `SF-D11` WITHDRAWN; `SF-D12` a corollary of `SF-D10`. **The
rule-26 halt is lifted:** implementation may begin, in the landing
sequence §9.1 fixes (2026-09-13): (a0) the v2 pass-countersignature
verifier alone → (a) serve side → (b) `shekyl-p-fetch` → (c) W₂ then
`N`. This file stays in `docs/design/` because it still owns named
residue — `L` (`SF-D8`; `archival_attestation_anchor_lag_blocks = 4`
PROVISIONAL; drop-to-3 is a candidate, not a pin), Sub-PR 2
(`PDM-Q6`), and SH-2. The integer `N` (`SF-D7`;
`shekyl_p_fetch::MAX_INFLIGHT = 8`) and the W₂ measurement are
discharged. Archives to `docs/completed/` when this file owns no named
residue (the "when (c) pins `N`" criterion expired 2026-09-16: `N` is
pinned and `L` / Sub-PR 2 / SH-2 remain). Organic draw bound `k`
is `TJ-D`'s, not this PR's.
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
route); discovery is ruled (`EU-D1`, `EU-D3`, `EU-D4` — the
JoinMarket-endpoint design; the rest of the `EU-` round was REJECTED
2026-09-13 with kind 4, see §4). Timeout/retry is
`SF-D6` (RULED) and
concurrency is `SF-D7` (RULED). The request-side carrier and
countersigning key are now ruled (`SF-D5` amendment; `SF-D13`), and so
is the complete response (`SF-D8`, RULED 2026-09-13, amended twice
later the same day — the second amendment is the one that landed: both
callers send requester-random bytes plus a **chain anchor**
`anchor_height ‖ anchor_hash` at `tip − archival_reorg_depth_blocks`;
`P` gates `anchor_height` against its own height (±`L`) and signs the
decoded 72-byte header ‖ `shard_id_le[8]`; admission looks the anchor
hash up on the connecting chain inside `[h−720−L, h−720]`; the
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
one caller ("fetch shard *s* from assigned `P`"). A daemon that needs
the shard (reconstruct, IBD-after-prune, operator test) is another
caller. They share the fetcher; they do not get a second path. There
is no leaf to extract: `RF-D8` retracted the opening;
`challenge_leaf_index` is deletion-bound. The challenge verifies `R_k`
over the whole shard.

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
| Discovery | `EU-D3`/`EU-D4` — endpoint = raw 32-byte Ed25519 key on the bond record; witness reads it from the drawable snapshot at epoch open, joined by `p_id` (`DrawablePair`, `rust/shekyl-archival-retention/src/challenge_assignment.rs:71`). **Producer RULED 2026-09-16 (SO-D8 Q3):** `DrawableSet::at_epoch_open` (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.4) | `SF-D5`'s input: key → onion is derivation, not lookup. `SF-D10` reads the holder set of `s` from the same snapshot |
| Derived assignment | [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §2: assignment for block *h* is a pure function of *h*−1's hash over the epoch-open drawable set. Public at *h*−1's publication; every node including `P` computes it identically. Witness = producer. Window = `CHALLENGE_RESPONSE_BLOCKS`. *(The v1 block-bound `attestation_nonce = H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` was deleted with `SF-D8` (a0), 2026-09-13.)* | Assignment stays derived. **It does not go on the fetch.** Both callers send requester-random bytes plus their own chain anchor at `tip − 720` (height and hash; `SF-D5` as amended). Nothing derived from the assignment is a request field |
| Request parse | `rust/shekyl-p-serve/src/serve.rs:558–560` — `path.strip_prefix(ROUTE_PREFIX)` then `parse::<u64>()`; comment: "Exact decimal id — no path suffix, no query string" | The request unit is a whole shard (`§4`) |
| Segment size | `rust/shekyl-curve-tree/src/segment.rs` — `LEAF_BYTES`; `shekyl_fcmp::tree::leaves_per_segment()` (re-exported there) | Honest-holder egress of a challenge fetch: one full segment (`leaves_per_segment() × LEAF_BYTES`) |
| Serving ↔ fetching Tor | `PWD-E9` ([`P2P_2_ENDPOINT_ROUND.md`](P2P_2_ENDPOINT_ROUND.md) §PWD-E9): daemon gets its own tor path, no crossover to the archival-serving persona; launch path takes instance identity as a parameter. Implemented 2026-09-09 (`DaemonTorControl`, `shekyl-tor-control-daemon`) | Closed. Constrains `SF-D2` (RULED): reuse is the **daemon zone's** SOCKS, never the serving persona's |
| Intro-layer PoW | `rust/shekyl-tor-control-wallet/src/onion_service.rs:146–148` — `HiddenServicePoW` defaults **on**; `rust/shekyl-tor-control-client/src/control/onion.rs:272–292` — PoW throttles rendezvous **arrival**, not egress; over onion the body transfer is symmetric (flow control). `control/actor.rs:1725–1754` — live `ADD_ONION` with PoW. Measurement: [`SP_T3_SKELETON_MEASUREMENT.md`](SP_T3_SKELETON_MEASUREMENT.md) SPIKE-F-15/17/18, §19/§19a | Threat-3 pin: intro flooding is priced; not general Tor lore |

## 4. Already closed — do not re-litigate

| Premise | Where |
| --- | --- |
| Test **is** a read; miners are ordinary clients; a distinguishable challenge path is teaching-to-the-test | TJ §9, §9.1 |
| Witness = producer of block *h* | Challenge mechanism fork 2 (ruled 2026-08-10) |
| Daemon is client; wallet is server; no wallet-to-wallet; HTTP-over-onion not a Levin message; RPC a separate layer; fetcher beside `shekyl-daemon-rpc` (process locality, not crate membership) | `EU-D1` |
| **Client crate is `shekyl-p-fetch`.** Counterpart of `shekyl-p-serve`. Codec is `shekyl-curve-tree` (shared, not mirrored). Virt-port home is `shekyl-curve-tree`. Not `shekyl-p-transport` (`PWD-E9`). Dependency cut is a gate: `scripts/ci/check_p_fetch_dep_cut.py`, LANDED 2026-09-13 by (b) (roots parsed from `BuildRust.cmake`, features resolved not grepped, `--selftest` in `grep-gates`) | `SF-D4` RULED 2026-09-12; gate LANDED 2026-09-13 |
| Endpoint = raw 32-byte Ed25519; address is display form; discovery is a chain read at the epoch-open drawable snapshot | `EU-D3`, `EU-D4` |
| Onions are enumerable (every `JoinMarket` publishes one; public is its normal state); the serve-side limiter (`shekyl-p-serve::serve::MAX_INFLIGHT`, SPIKE-PIN-2) is load-bearing. **`EU-D6` REJECTED 2026-09-13** as a rotation-rate argument; the enumerability fact and the limiter survive on their own code anchors, not on `EU-D6` |
| **`EndpointUpdate` (kind 4) REJECTED 2026-09-13** — a bonded persona's endpoint never changes; the endpoint is mandatory on `JoinMarket`, non-zero by consensus, immutable for the record's life (`EU-D3` narrowed). A new address is a new persona via Release + fresh `JoinMarket`. `EU-D2`, `EU-D5`…`EU-D13` rejected with it. Consequence for this round: "no endpoint on record" is unrepresentable, so `SF-D6`'s no-endpoint non-row collapses (see `SF-D6`), and `SF-D13`'s "onion key may rotate" reason is refuted (see `SF-D13`) | `EU` §1, §5 |
| `GET /shard/{id}`; identical 404s for every non-servable outcome; only content-type + content-length on the response; hand-rolled HTTP/1.1 | `RF-R1` |
| **Request-header amendment RULED 2026-09-13 (second amendment; verifier half LANDED by (a0); serve half and client LANDED by (a)+(b): header `shekyl-pass-request`, value lowercase hex of the 72 bytes, `serving_route::{REQUEST_HEADER_NAME, encode_request_header, decode_request_header}`):** exactly one named header is required and decodes canonically to 72 bytes `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]` — fresh random for every request, both callers, plus a chain anchor at `tip − archival_reorg_depth_blocks` (720): the height and the requester's own block hash at it. `P` applies one pre-sign gate, `anchor_height ∈ [p − 720 − L, p − 720 + L]` with `p` its own height and `L = archival_attestation_anchor_lag_blocks` (4, PROVISIONAL), else the identical 404. Missing, malformed, duplicate, wrong-length, or out-of-gate values are the same identical complete-head 404. All other request headers remain ignored. Exact header spelling and canonical textual encoding land code-plus-tests first under `RF-R1`'s transcription discipline, then the living contract records them in the same implementation PR. `P` signs the **decoded** 72 bytes, never the textual form | `SF-D5` amendment; verifier (a0) `#734`; serve-side carrier is the `shekyl-p-serve` PR (a) |
| **Request unit is a whole shard.** `{id}` is an exact decimal `u64`; no suffix, no query string (`RF-R1` request grammar; `serve.rs:558–560` parses exactly that). There is no leaf addressing. The challenge caller fetches the full segment and verifies `R_k` — that is the TJ §9 topology working as designed (the honest holder's egress is the cost being measured). There is no leaf to extract locally (`RF-D8` retracted the opening). `RF-R1`'s reopening clause permits "an additional path that suffixes `/shard/`" if a later request contract is needed; that suffix is exactly where a leaf-addressed challenge fetch would enter, and it is the natural optimization for anyone looking at ~3.33 MB per challenge. **`SF-D1` holds that door shut:** any future suffix path must be usable by both callers, or it is a second path by another name | `RF-R1`; `SF-D1` |
| **Serving and fetching do not share a Tor instance.** `PWD-E9` (RULED 2026-09-08, implemented 2026-09-09): the daemon gets its own tor path with no crossover to the archival-serving persona; the launch path takes instance identity as a parameter, so sharing the code cannot produce a shared instance. The ratified §7 guard residual splits one application's identities; E9 forbids two applications sharing one instance, and the ephemeral/durable asymmetry makes the crossover strictly worse. **`SF-D11` withdrawn** — asked in this round, then closed by reading `PWD-E9` | `PWD-E9` |
| **Fetch outbound reuses the tor zone's existing SOCKS, unconditionally.** No second Tor process. No manufactured SOCKS reopen. The object of reuse is the **zone proxy** (`zone.m_proxy_address` / `socks_connect`), not always `DaemonTorControl` — `--tx-proxy` / `--anonymous-inbound` already yield the managed instance and still leave a tor-zone SOCKS. The daemon image passes that `SocketAddr` into `shekyl-p-fetch`; the crate does not discover SOCKS. PWD-E7 is not re-ruled. Shared-instance residual (P2P ↔ archival-fetch on one process) is accepted (§7 threat 4) and is the `SF-D3` ruling, not a leftover | `SF-D2` RULED 2026-09-12 |
| **Unauthenticated SOCKS, no isolation flags.** The fetch client presents no SOCKS credentials and sets no isolation flags on the zone proxy. Circuit assignment is Tor's, per its own defaults — this is not a one-circuit guarantee. Fetches then share circuits with overlay P2P (no credentials on the same SOCKS); that blending is a consequence, not a cover mechanism. Cover is TRC's subject | `SF-D3` RULED 2026-09-12 |
| **The virtual port is 80**, a shared constant both sides read from `shekyl-curve-tree` (`SF-D4` named the home). Today's `SERVING_VIRTUAL_PORT` is `pub(crate)` in `shekyl-engine-core` (`serving/task.rs:52`) — the current location, not the home; the implementation PR moves it. Two `80`s that happen to agree are still not the ratification — this row is the number; the implementation PR puts one constant in `shekyl-curve-tree` and both sides read it. **Request amendment:** same `GET /shard/{id}`, one required header decoding to `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`, no path token, query string, or body; every production call uses it | `SF-D5` RULED 2026-09-12; AMENDED 2026-09-13 (×2) |
| **Timeout / miss / retry taxonomy.** One table, two caller columns. Per-attempt handling is the client's (`SF-D1`); the axis is whom the scheduler names next and what exhaustion means. Organic draw bound `k` is the fill scheduler's (`TJ-D`), not the fetch crate's (`client-need` on remaining-empty or `k`). No-endpoint on the bond record is unrepresentable (`EU-D3` narrowed 2026-09-13), so the former filter / pre-dial non-row is void. 404 is a completed exchange (immediate miss), not a retry. Over-capacity silent close is stall-class (`RF-R1`), not a 404. Any other complete-head is malformed. Stall retries of that `P` reuse the same 72-byte header. `content-length` above `signature_envelope_len + max framed_len()` is refused from the HTTP headers; otherwise it must equal `signature_envelope_len + framed_len()`, known after fixed metadata but before segment bytes. The envelope is a fixed-width slice, then parsed. Parse, root-mismatch, and bad-countersignature remain typed separately. Reopen if W₂ retry budget and `CHALLENGE_RESPONSE_BLOCKS` cannot coexist | `SF-D6` RULED 2026-09-12; AMENDED 2026-09-13 |
| **One fixed client in-flight cap `N`, one shared admission path, no caller differentiation.** Challenge and organic use the same client code, admission, and request; no priority, reservation, caller tag, or second entry point. The API is `fetch(&FetchTarget, &header, verifier)` — **AMENDED 2026-09-13, implemented 2026-09-14:** the target is typed (`ServingEndpoint`, `HybridPublicKey`, `u64`); expected content is the per-call `ContentVerify` hole, caller-supplied from local chain state, never from a response; schedulers name `P`; the HTTP path names only `s`. `N` slots, no unbounded buffer: a scheduler waits for a slot. `N` is also `N × SHARD_BYTES` on the Pi 4 floor (the client materialises the segment to verify `R_k`). Not organic draw cap `k` and not a function of `D`. SP-T3 re-base / W₂ owns the upper bound as min(circuit-churn, memory); the implementation PR owns the lower-bound judgement. Reopen if capped reconstruct throughput falls below TJ-D's chain-growth requirement, or wait-for-a-slot plus transfer approaches `CHALLENGE_RESPONSE_BLOCKS` | `SF-D7` RULED 2026-09-12; AMENDED 2026-09-13 |
| **Organic selection is a uniform memoryless draw** over the drawable holder set of shard `s`, performed by the organic scheduler, not by `shekyl-p-fetch`. Per-need exclusion is scratch, not memory. The fetch client forms no opinions — it is given a destination | `SF-D10` RULED; `SF-D12` corollary |
| **Countersign with the bond record's hybrid identity key**, `BondPost.hybrid_public_key`, both Ed25519 and ML-DSA legs. This rules the key, not the message (the message is `SF-D8`'s). This is not the onion key and never the cold `bond_spend_pk`. `shekyl-p-serve` holds no key material: `PServeEndpoint` takes a signer callback; tests inject a test key; SH-2 wires the persona secret. The onion endpoint is authenticated by the Tor rendezvous and bound beside the identity key on P's authorized bond record; the response signature proves the live responder also controls P's identity key | `SF-D13` RULED 2026-09-13 |
| **The signed message is the decoded header ‖ `shard_id_le[8]`: `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8]`** (80 bytes) — requester-random, the requester's chain anchor at `tip − 720`, then the `u64` `P` parsed from `/shard/{id}`, under `shekyl/archival-attestation-scheme-v2` (the v1 nonce-only domain is retired). The challenge tuple and `cb_out_key` are not in this message: the fetch proves `P` served, not which miner asked. `shard_id` stops a decoy-route signature being filed as a pass for a different shard. The pass record **carries** `nonce` and `anchor_height` (neither is recomputable); admission rebuilds the transcript with the connecting chain's hash at `anchor_height`, requires `anchor_height ∈ [h − 720 − L, h − 720]` with `h` the validated predecessor, and refuses every pass record while `h < 720 + L` (724). Domain string, fixture, and boundary KATs (723/724) LANDED 2026-09-13 by (a0) | `SF-D8` message half RULED 2026-09-13; AMENDED 2026-09-13 (×2); LANDED (a0) |
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
same client entry point `fetch(&FetchTarget, &header)` (`SF-D7`) — "you
produced block *h*: fetch shard *s* from assigned `P`" and
"this daemon needs shard *s*" — and tests are a third scheduler of
that same entry point, not a separate path. **UPDATE 2026-09-14:** the
operator GUI's `request_archival_shard` JSON-RPC is a **fourth scheduler of
the same `fetch()` entry**, not a wallet client (`SL-D8` §10.2). The wallet
names `shard_id` only; the daemon draws `P` (`SF-D10`) and holds the same
in-flight cap `N` with no priority over challenge/organic. Every node is a
full node and every node prunes: shard bodies below the window live with
stakers, or temporarily on a daemon that requested the shard to view. A
freeze-row `R_k` is consensus metadata, not a body, and is not a local
shortcut around fetch. Answering from bytes this node already holds
(staker set, or a prior view-cache) is still this scheduler, not a second
protocol. The HTTP request names only the shard; the destination is whom
the scheduler named, not a caller tag on the wire.

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
`SF-D5`/`SF-D8` were amended later the same day, twice: first to
requester-random plus published-tip height (SUPERSEDED the same day,
never landed), then to requester-random plus a buried chain anchor
`anchor_height ‖ anchor_hash` with a `P`-side height gate — the shape
the (a0) PR landed. The challenge tuple is not on the fetch under
either.

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

**Composition hands in a `SocketAddr`.** `shekyl-p-fetch` does not
discover SOCKS and does not depend on `shekyl-daemon-rpc` (`SF-D4`
dep-cut). The daemon image passes the zone proxy address into the
client — `zone.m_proxy_address` from C++, or
`DaemonTorControl::socks_addr()` when that is the zone. `--tx-proxy`
is still that address, not a second lookup.

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

**Codec shared, not mirrored.** Sub-PR 1's client is not unit-aware:
the body is `Vec<u8>` handed to a per-`fetch` [`ContentVerify`] hole.
`shekyl-p-fetch` depends on `shekyl-curve-tree` for the *route grammar*
(`serving_route`: port 80, `/shard/`, header name and hex codec,
response header set) and for `leaves_per_segment` / `LEAF_BYTES` as
the provisional body-ceiling inputs. Frame parse and `R_k` recompute
are the hole's (sub-PR 2, `PDM-Q6`). A private copy of the grammar
agrees until it doesn't; one constant read twice is the ratification.

**Virt-port home.** The ratified port is 80 (`SF-D5`), a constant both
`p-serve` and `p-fetch` read from `shekyl_curve_tree::serving_route`.
`shekyl-engine-core`'s serving task is a `pub(crate) use` of that
declaration. The onion hostname is *not* this constant: it is
`shekyl-onion-v3`, typed on the daemon as `shekyl-p-fetch::ServingEndpoint`
and on the wallet as `OnionIdentity` (`PWD-E9`).

**Dependency cut is a gate, not a sentence.** LANDED 2026-09-13 by
(b) as `scripts/ci/check_p_fetch_dep_cut.py` (Python over manifests,
not the `.sh` first named: the properties are transitive-closure
facts a line-grep cannot see, and grep-gates has no toolchain for
`cargo metadata`; same fail-closed rule-47 shape as
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

**Request-header amendment (RULED 2026-09-13; AMENDED twice later the
same day — the second amendment is current).** Every request carries
exactly one named header whose one canonical textual encoding decodes
to exactly 72 bytes: `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`.
Both callers, every request:

- `nonce` is fresh cryptographically random 32 bytes. No two requests
  reuse it. It is **not** `attestation_nonce`. The challenge tuple
  (`block_hash(h−1)`, `cb_out_key`, `P`, `s`, `E`) does not go on the
  fetch — that hash names the assignment, and putting it on the wire
  lets `P` serve the witness and refuse everyone else.
- `anchor_height` is `tip − archival_reorg_depth_blocks` (720) at
  request time, as a little-endian `u64`, and `anchor_hash` is the
  requester's own block hash at that height. A block 720 deep is the
  segment-freeze depth (`SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`, generated
  from the same JSON key and const-asserted equal in
  `tests/attestation_wire_kat.rs`): identical on every
  honest node's chain, so races at the tip cannot make an honest
  requester's anchor fail, and every miner building on the same tip
  sends the same anchor. It is freshness, not identity: it does not
  name the assignment.

**`P`-side gate (RULED 2026-09-13; LANDED by (a) —
`shekyl_p_serve::anchor_within_gate`, run before the shard lookup).** Before signing, `P` checks
`anchor_height ∈ [p − 720 − L, p − 720 + L]`, where `p` is `P`'s own
height and `L = archival_attestation_anchor_lag_blocks` (4,
PROVISIONAL). Out of gate is the identical complete-head 404. The
**upper** bound carries freshness against a non-colluding witness: a
requester that fetched at height *T* with `anchor = hash(T − 720)`
would otherwise hold a signature admissible at *h* = *T* + 720, a day
later; with the gate it gets a 404. The **lower** bound is hygiene.
The gate is **two-sided with the same `L`** so a `P` one block behind
does not refuse the whole network, and so no `P` gates distinctively.
`P` needs a **height**, not a chain: one `u64` the host supplies from
the same loopback the claim leg already requires (`SF-D13`);
`shekyl-p-serve` stays a blind signer over requester bytes with no
daemon dependency (`SF-D4` dep cut intact). **Residual, recorded:**
the gate leaks whether `P` is synced — a requester can binary-search
`P`'s height through 404s. A synced `P` answers like every other synced
`P`, and an unsynced one is already failing challenges, so the leak is
"synced or not", which is not identity. Accepted.

`P` treats the decoded 72 bytes as opaque input to `SF-D8`'s
response-binding transcript — the gate reads `anchor_height`, nothing
else is interpreted. It does not infer which caller this is.

This rules the **carrier**, not the signed message. The request parser
hands `(header_bytes, shard_id)` to the response-binding seam; `SF-D8`
fixes the signed transcript as the **decoded** 72 bytes in canonical
binary followed by `shard_id_le[8]` — never the header's textual form,
so Rust and C++ cannot disagree the first time a case or padding
variant is accepted on the wire.

*Records-was (first amendment, SUPERSEDED the same day, never
landed):* 40 bytes `nonce[32] ‖ height_le[8]` with `height` the
published tip and admission requiring equality with the predecessor
height. Refuted because a requester-chosen integer proves nothing
about when the fetch happened — `P` signs blind and a lone witness
pre-fetches for any future height — and because exact equality misses
every honest fetch that spans a block boundary.

The header's **presence and shape** are ruled here. Its exact spelling
and canonical textual encoding followed `RF-R1`'s transcription
discipline and are LANDED by (a): `REQUEST_HEADER_NAME =
"shekyl-pass-request"`, value the lowercase hex of the 72 bytes
(`serving_route::encode_request_header` / `decode_request_header`,
name matched case-insensitively, value strict), pinned by
`request_header_parsing_is_http_lenient_and_value_strict` and recorded
in [`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md) in the same
change. This is a concrete carrier, not permission for more fields.
Missing, duplicate, malformed, or wrong-length values are a
complete-head miss and render the same byte-identical 404 as every
other non-servable outcome. All other request headers remain ignored.

**The only semantic request fields.** The 72-byte header is the only
recognized caller-supplied field other than the selected shard id.
Both production callers use one serializer and vary only
`(shard_id, nonce, anchor)`. The anchor is a deterministic function of
the requester's tip, so at any moment both callers send the same
anchor distribution. This is the
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
  port cuts an enumeration or scanning class (onions are enumerable
  from `JoinMarket` posts; `EU-D6` itself is REJECTED); or
  the implementation cannot express one canonical 72-byte
  `nonce ‖ anchor_height ‖ anchor_hash` representation without adding
  a second request field; or the W₂ / PD-F-2 dispersion measurement
  moves `L` (see `SF-D8`'s PROVISIONAL note for the direction rule).

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
- **No endpoint on the bond record — VOID 2026-09-13, unrepresentable.**
  This was ruled 2026-09-12 as a chain-state non-row (organic: filter
  from the draw; challenge: pre-dial immediate miss), with a named
  operator failure mode — an `EndpointUpdate` not yet landed, or a
  record whose endpoint was never set — accruing misses for a whole
  window. The `EU` kind-4 rejection (`EU-D3` narrowed 2026-09-13)
  removes the premise: the endpoint is **mandatory on `JoinMarket`**,
  a non-`Option` field, all-zero refused by consensus on both sides,
  and **immutable for the record's life**. A drawable `P` therefore
  always has exactly one endpoint, from the same snapshot that named
  it (`EU-D4`). There is no filter to apply, no pre-dial branch to
  take, and no slash-accruing "unpublished" state for an operator to
  be warned about — the case cannot be constructed. What remains of
  the old split is one thing: an endpoint that is on the record but
  has no live descriptor is a **transport** outcome and files under
  the stall-class row above, exactly as SOCKS CONNECT / intro failure
  does. The stall-class row's "(endpoint *was* on the record)"
  qualifier is now always true and is kept only as a record of the
  split it used to make.

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
**must agree**. Disagreement is malformed, not truncation.

**Pre-read cap.** A hostile `Content-Length: 2^63` is refused **from
the HTTP headers**, before any body byte, if it exceeds
`signature_envelope_len + max framed_len()` (`RF-D7`'s padding cap,
already enforced inside `ServedFrameHeader::read`). That is a
malformed row, not a drain. Agreement with `framed_len()` is still
checked after the envelope and `ServedFrameHeader` have arrived and
**before segment or padding bytes**. It is still an immediate miss:
a hostile `P` cannot make the client consume a shard body before
discovering the disagreement. Truncation is: they agreed on `N`, and
fewer than `N` total body bytes arrived. Overlength is: they agreed
on `N`, and more than `N` total body bytes arrived.

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
| Circuit timeout / HTTP stall / SOCKS CONNECT or intro failure / over-capacity silent close (endpoint *was* on the record). `RF-R1`: over-capacity arrivals are closed with **no HTTP bytes**, not a 404 | Stall-class: bounded retries of **that** `P` inside the deadline, then **miss** | Stall-class: same per-attempt retries; then exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Body short of agreed `N` (truncated transfer) | Stall-class | Stall-class |
| Body long of agreed `N` (overlength) | Malformed → **miss** | Malformed: exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| `content-length` > `signature_envelope_len + max framed_len()` (refused from the HTTP headers, before any body byte) **or** `content-length` ≠ `signature_envelope_len + framed_len()` (known after the frame header, before segment bytes) | Malformed → **miss** | Malformed: exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Identical 404 (`RF-R1`) | **Miss.** Completed exchange; `P` answered "no." Do not retry **that** `P`. Identical 404s are why the client must not distinguish *which* "no" | Exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Complete-head that is not `200` with exactly `content-type` + `content-length`, and not the identical 404 (`301`, `500`, extra headers, wrong content-type) | Malformed → **miss** | Malformed: exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Malformed response envelope / frame | Malformed → **miss**. Logged (`SF-D12`); not a selection input | Malformed: log; exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| `R_k` mismatch | Root-mismatch → **miss**. Typed and logged (`SF-D8`, `SF-D12`); not a selection input | Root-mismatch: log; exclude, draw next. Cap/`k` or remaining-empty → **client-need** |
| Countersignature invalid for `SF-D8`'s ruled `header[72] ‖ shard_id` transcript under P's bond-record hybrid identity key | Bad-countersignature → **miss**. Typed and logged (`SF-D8`, `SF-D12`); completed response, so no retry of that `P` | Bad-countersignature: log; exclude, draw next. Cap/`k` or remaining-empty → **client-need** |

- **Amendment 2026-09-13:** the last three rows split parse failure,
  `R_k` mismatch, and bad countersignature into distinct verdicts.
  Their scheduler consequence is intentionally the same; their typed
  errors are not.
- **Stall retries reuse the header.** Per-attempt handling is
  identical for both callers: retries of **that** `P` resend the same
  72-byte `nonce ‖ anchor_height ‖ anchor_hash`. A new destination
  (organic draw-next, or a new challenge) gets a new random; the
  anchor is `tip − 720` at that new request. Minting a new nonce on
  stall retry of the assigned `P` would make a later pass record fail
  admission (wrong random). Retries are also why `L` is sized by
  fetch-plus-retry span, not by fetch alone: the anchor is fixed at
  first attempt and admission needs it inside `[h−720−L, h−720]` at
  the block that finally carries it.
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

### `SF-D7` — concurrency vs growing `D` — RULED 2026-09-12; AMENDED 2026-09-13 (typed target)

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

**The integer was unpinned at ruling (2026-09-12); PINNED `N = 8`
2026-09-16 (amendment below).** This round rules the *shape* (one fixed
`N`, one shared admission path, `fetch(&FetchTarget, &header)` for
both callers — target typed per the 2026-09-13 amendment below). Caller-blind is the HTTP request, not the API:
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
  the same `fetch(&FetchTarget, &header)` for challenge and
  organic requests (target typed; amendment below). No priority or reservation. Concurrent transfers,
  not `k`, not circuit-build cost, not a per-`D` scaling constant.
  Integer PINNED `N = 8` (`shekyl_p_fetch::MAX_INFLIGHT`, (c),
  2026-09-16): largest non-churning measured width; memory
  (`8 × max_body_bytes() ≈ 53 MB` at the leaf figure) does not bind.
  Widths 1/2/4/8 all valid, zero serve-side sheds. Raising above 8 is a
  new sweep (16 was not measured). Re-derive the memory term under
  `PDM-Q6`. The constant's doc carries the reopen criteria.
- **Reopen if:** reconstruct throughput at the cap falls below what
  TJ-D's fill scheduler requires to keep pace with chain growth; or
  wait-for-a-slot plus transfer for a challenge request approaches
  `CHALLENGE_RESPONSE_BLOCKS`. Not reopened by coverage math at
  maturity — that quantity cannot answer this question.

**AMENDMENT 2026-09-16 — the integer is pinned `N = 8`.** The W₂
run (PR #746) measured widths 1, 2, 4, 8 over the production
`PFetchClient` (daemon→wallet, one client tor, 3.33 MB shard-0).
All four rows valid; circuit-failure 0.0 / 1.0 / 0.0 / 0.0 %; p50
12.41 → 13.21 s; width-8 resident 53.2 MB. Pin =
`min(largest non-churning width, Pi 4 memory)` = 8 (memory does not
bind). 16 was not measured. The constant's doc carries the reopen
criteria (`SF-D7`) and the `PDM-Q6` re-derive.

**AMENDMENT 2026-09-13 — the fetch target is typed, caller-supplied,
and read from local chain state.** `fetch(destination, shard_id,
header)` named three inputs. `SF-D8`'s seam needs two more *before the
dial* — the expected root and `P`'s verifying key — because no store
handle exists at verify time (TJ-F liveness). Left unnamed, an
implementer adds them as bare arrays, which is the `RF-D6` defect one
layer up: a wire-shaped value the crate trusts because the caller
handed it over. Caller-supplied and bare-bytes are not the same
thing; the reconciliation is the type. The entry point is

```text
fetch(target: &FetchTarget, header: &RequestHeader, verifier: Arc<dyn ContentVerify>)
    -> Result<VerifiedShard, FetchError>

FetchTarget {
    endpoint:      ServingEndpoint,        // shekyl-p-fetch (daemon dial target)
    verifying_key: HybridPublicKey,        // shekyl-crypto-pq
    shard_id:      u64,
}
```

The ruled `expected: FrozenSegmentRecord` is the content-verify hole's,
not the target's: sub-PR 1 is not unit-aware, and putting the record on
`FetchTarget` would leak the leaf figure into the transport crate.
Two callers share one `PFetchClient` (one in-flight cap) and plug the
hole per call.

- `verifying_key` is the `HybridPublicKey` type, not 32+1952 bytes.
- `ServingEndpoint` is the daemon's typed dial target over the
  bond-record endpoint column; the wallet publishes through
  `OnionIdentity`. Same rend-spec transform (`shekyl-onion-v3`),
  different types (`PWD-E9`). `BondPost.endpoint` is a
  bare `[u8; BOND_POST_ENDPOINT_LEN]` on the genesis-frozen wire and
  stays bare (rule 42 — the wire is not touched for type hygiene).
  The newtype is minted in `shekyl-p-fetch` (the daemon is who dials);
  onion-address derivation is `shekyl-onion-v3`. `shekyl-wire` cannot
  be its home: it depends on
  `shekyl-archival-retention` and `shekyl-tx-builder`, and the fetch
  crate taking it would breach the `SF-D4` cut. The caller builds the
  newtype from the **record** read (`ArchivalBondValue` endpoint
  column), never from the vin.
- Every field is obtained from local chain state — the drawable
  snapshot through the record (`EU-D4`) and the local frozen-segment
  store — and **never from a response**. The crate still reads no
  chain state and still depends on nothing but `shekyl-curve-tree`
  and `shekyl-crypto-pq`; the types carry the provenance obligation
  the crate cannot check itself. A call site that constructs any of
  these from wire or response bytes is a rule-19 violation the review
  catches.

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
The callback (`shekyl_p_serve::PassSigner`; `shekyl_p_host::{PassKey,
HostSigner, NoResidentKey}`) and the envelope LANDED by (a); SH-2
wires the live secret — until then `engine-core` binds `NoResidentKey`
and every serve is a counted sign refusal. The unsigned HTTP half is not a
substitute for a countersigned loopback test.

**Named residency: the serving host becomes a hot signer.** Every
read now costs a hybrid signature with `P`'s identity secret, so that
secret is resident in the serving process for as long as it serves —
derived, scoped, and zeroized under rules 35 and 36, behind the
callback, never in `shekyl-p-serve`'s own types. This is consistent
with the custody model already accepted (`EU` §1, 2026-09-13: host
compromise yields the serving seed and the identity signing key; the
remedy is Release under the never-on-host `bond_spend_pk`, then a fresh
persona), but it is a residency the serving task
does not have today: `shekyl-p-serve` was built never to hold a secret.
It is named here so the implementation PR and SH-2 design the
residency rather than discover it the first time the serve path needs
to sign.

**Second named input: a height, not a chain (added with the `SF-D5`
second amendment, 2026-09-13).** The `P`-side anchor gate needs `P`'s
own height to within `L`. That is one `u64` the host passes in beside
the signer callback, read from the same loopback the claim leg already
requires; a value within `L` of true is sufficient, so the host need
not hold a validated tip, only a validated height. `shekyl-p-serve`
still holds no chain view and takes no daemon dependency.

**Test-key injection is an armed test affordance, not a config
surface (added 2026-09-13).** The loopback acceptance test signs with
an injected key. A key-injection path that survives into a production
build is how a persona ends up signing with a test key, so the
affordance takes the `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` shape
(`shekyl-archival-retention/src/constants.rs:230`): armed explicitly
by the test, pinned, refused loudly on a bad value, and **asserted
absent in release builds** by a gate that fails when the arming symbol
is reachable there (rule 47 — the gate proves the subject exists in
test and does not in release). Not an environment variable a deployed
`shekyl-p-host` could read.

This ruling selects the **key only**. The signed transcript is
`SF-D8`'s — `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖
shard_id_le[8]`, LANDED by (a0) in `verify_pass_countersignature`
(`shekyl-archival-retention/src/attestation_wire.rs`, transcript in
`pass_anchor.rs`). The v1 nonce-only message that function verified
before (a0) is RETIRED: caller-supplied opaque nonces invalidated its
premise that a nonce containing `shard_id` is by itself a
server-enforced shard binding, which is why `shard_id` is now an
explicit transcript term.

Two same-neighbourhood keys are expressly **not** selected:

- not the raw onion endpoint key as the Ed25519 leg. *(The reason
  first written here — "may rotate through `EndpointUpdate`" — is
  REFUTED 2026-09-13: the endpoint is immutable, so both keys are
  equally stable.)* The reasons that stand: the onion key has no
  ML-DSA sibling, so it cannot produce the hybrid signature `RF-D2`
  requires at all; it is the rendezvous-authentication key and giving
  it a second signing role crosses key-separation for no gain; and
  `p_canonical_id` is the hash of the hybrid identity key, so that is
  the key the verifier already binds to the record;
- never `bond_spend_pk`, the cold debit authorizer that does not cross
  into the serving tree.

No sibling proof-of-possession field is added to the bond wire. The
authorized bond record binds the endpoint key beside P's hybrid
identity key; the Tor rendezvous proves control of the endpoint key;
the countersigned response proves that the live responder also
controls P's hybrid identity key. Online cooperation remains the
already-accepted fully-collusive case; an additional static proof does
not remove it.

- **Reopen if:** grounding the `JoinMarket` authorization preimage
  shows the endpoint bytes are not covered by
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
   transcript `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖
   shard_id_le[8]` — the decoded 72-byte header this request sent,
   followed by the `u64` this request asked for.

No store handle exists at verify time (TJ-F liveness). The two
verification refusals are distinct typed errors — `RootMismatch` and
`BadCountersignature`; response-envelope/frame decode remains its own
parse error rather than being folded into either. `SF-D6` gives all
three the same scheduler consequence while preserving the diagnostic
distinction.

The successful type retains the countersignature beside the verified
shard. Both callers verify it — "verified-or-refused" is caller-blind,
so a `P` that signs badly is refused by every requester, which is what
keeps the client uniform. The witness caller then keeps the signature
for pass-record construction; the organic caller has no further use
for it. Both receive the same type from the same call. Pass-record construction itself is **out of
scope** — the type this round names is the input that round consumes.
Reconstruct's "install these leaves" is also out of scope (TJ-D
storage); it consumes the same typed result.

**Request side is closed.** `SF-D5` carries the 72-byte header: same
`GET /shard/{id}`, one required canonical
`nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`, no path token,
query string, or body. Both callers generate a fresh random `nonce`
and attach their chain anchor at `tip − 720`. `P` gates the anchor
height against its own (`SF-D5`), parses `{id}`, and constructs the
signed transcript from the decoded header plus that id.

**The fetch proves `P` served, not which miner asked.** Binding
`cb_out_key` or the rest of the challenge tuple into the request
would name the assignment on the wire. Same-height reuse of a
signature across competing blocks still happens and is still fine:
every miner building on tip *T* sends the same `hash(T − 720)`, so
Alice fetched, `P` served, and Bob's winning block may carry that
evidence. The 2-of-3 counts whether `P` served, not who asked.
(Anchoring at the **tip** hash instead would have lost this — a `P`
that saw the losing side of a same-height race first would sign a hash
that never becomes canonical and eat an unpriced miss. Burying the
anchor 720 deep keeps it; see the residual below for what it costs.)

**Grounding finding — a signature that does not cover the parsed
route id is a confused deputy.** The caller chooses the random
bytes, so signing them alone (or them plus height) does not bind the
signature to `/shard/{id}`: a dishonest witness can request a held
decoy while filing the signature as a pass for an unheld target.
Appending the server-parsed shard id makes that signature fail for
`target`. This is not additional evidence against a fully collusive
P+witness; that residual remains priced by the ruled 2-of-3 quadratic.

**Signed message — RULED 2026-09-13; AMENDED twice later the same
day (second amendment current).** `P` signs one fixed,
domain-separated encoding of
`nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8]`
(80 bytes), where the first 72 bytes are the **decoded** header in
canonical binary exactly as received — never the header's textual
form — and `shard_id` is the exact `u64` `P` parsed from this
request's `/shard/{id}`. Both signature legs cover that message. The
fetch client reconstructs it from the header it sent and the shard id
it requested; it never reads those values back from the response.

The pass record **carries** the 32-byte `nonce` and the 8-byte
`anchor_height` — the random cannot be recomputed from chain terms and
the height is the requester's choice inside a window, so neither is
derivable at admission. That reverses the credit-wire line that the
nonce is not stored (+40 bytes per witness entry versus v1). The
**anchor hash is not carried**: admission reads it from the
**connecting chain** at `anchor_height`, which is exactly what makes a
fabricated hash fail. Admission of a challenge pass in a block whose
validated predecessor is at height `h`:

- requires `anchor_height ∈ [h − 720 − L, h − 720]` — the upper bound
  is `h − 720` because the requester anchored at its own tip minus
  720, and its tip is at most `h`; the lower bound absorbs fetch span
  (including `SF-D6` stall retries of the same `P`, which reuse the
  header), `P`/requester skew, and the miner ending up building
  *h*+1 with an anchor chosen for *h*. Outside → `AnchorOutOfWindow`;
- rebuilds the transcript with the connecting chain's block hash at
  `anchor_height` — main chain, or the alt chain **above the fork
  point** when the block is being validated on an alt chain (nothing
  caps reorg depth, so a main-chain-only lookup would be a consensus
  split waiting for a deep reorg) — and verifies under `P`'s bond
  hybrid key. Mismatch → `BadCountersignature`;
- refuses **every** pass record while `h < 720 + L` (724): no anchor
  exists yet. First settlement is at 10 000, so nothing is lost.
  Boundary KATs at 723 (refuse) and 724 (accept), Rust, FFI, and C++.

**Constants, single-sourced.** Depth is the existing
`archival_reorg_depth_blocks` (720, `config/consensus_constants.json`),
which gains a third consumer; `SEGMENT_FREEZE_REORG_MARGIN_BLOCKS`
(`segment.rs`) is generated from the same key since 2026-09-18, and
`shekyl-archival-retention/tests/attestation_wire_kat.rs` const-asserts
`PASS_ANCHOR_DEPTH_BLOCKS` (an alias of retention's generated
`ARCHIVAL_REORG_DEPTH_BLOCKS`) equal to it — since the dedup that pin
guards the two `build.rs` readers agreeing, not a hand literal — and the JSON
comment now names **both** danger directions — lower makes the anchor
reorg-sensitive and re-introduces honest fork misses; higher lengthens
the collusive pre-signing lead — plus the `PDM-Q11` `D_max` gate as a
consumer. `L` is the new `archival_attestation_anchor_lag_blocks`
**= 4, PROVISIONAL**, `build.rs`-enforced `≥ 2`, read by Rust; C++
sizes the window through `shekyl_archival_pass_anchor_window` and holds
no copy. The verifier reads the generated constants, never a third
literal.

*`L = 4` — why, and how it moves.* The asymmetry decides the direction:
too small produces honest witness misses (unpriced, landing on
operators); too large costs one block of pre-fetch lead per unit
against a 720-block floor and one block of epoch slack per unit
against 10 000. So err large. What it must cover: fetch span plus
skew. The only measured fetch figure is a burst floor near 180 KB/s
(~20 s for 3.33 MB) — a floor from a null result, not a sustained
figure — and `SF-D6`'s bounded retries against a stalling `P` can
stretch one witness attempt to several minutes. Two blocks of span
(four minutes of fetch-plus-retry), one block of `P`/requester skew,
one of margin: four. **Falsifier:** the W₂ / PD-F-2 dispersion
measurement, in either direction. If p99 fetch-plus-retry lands under
two minutes, drop to 3. If it lands over six, the answer is **not**
"raise `L`" — it is that `SF-D6`'s retry budget is too generous,
because `L` would be absorbing what the budget should bound. The
re-pin must not simply track the measurement upward.

**W₂ 2026-09-16 (single-attempt, PR #746):** cold p99 = 48.27 s;
soak p99 = 86.06 s; both under 120 s. Verdict: DROP-TO-3 CANDIDATE —
necessary, not sufficient. Seven attempts of the cold p99 fit under
six minutes. `L` stays 4 until fetch-plus-retry exists (`SF-D6` /
TJ-D). Soak p99 does not walk the candidate back and does not pin.

**Residuals, recorded rather than inherited:**

- *720-block collusive lead.* Burial depth is lead time: a `P` that
  skips its own gate can, at tip *T*, sign a pass anchored `hash(T)`
  that is admissible at *h* ∈ [*T* + 720, *T* + 720 + *L*] — a day
  out — and sign the coming day's worth for a colluding requester in
  one sitting, then go offline. The honest gate refuses that anchor;
  only collusion produces the lead. Fork immunity and short lead are one knob pulling opposite
  ways; there is no depth that gives both. Fork misses hit honest
  operators and nothing prices them; collusion lead hits the mechanism
  only under collusion, which the 2-of-3 quadratic already prices, and
  a day of lead changes how often colluders talk, not the arithmetic.
  A middle depth (10–20 blocks) is better on both axes but introduces
  a new "this depth is safe" assumption nothing else relies on; 720
  introduces none. Accepted, priced.
- *Freshness against a non-colluding witness is structural, not
  economic.* With the anchor requester-supplied and **no** `P`-side
  gate, a lone witness at height *T* could send `hash(T)` and hold a
  signature usable at *T* + 720; the attack costs the whole archival
  set's bandwidth daily and was impractical, but "impractical" is
  economics. The `SF-D5` gate makes it a 404. Recorded so the property
  is not later read as depending on bandwidth.
- *Binary-search leak from the gate* — `SF-D5`. Leaks "synced or not",
  not identity.
- *`L` against the 10 000-block epoch.* A pass anchored in the last
  `L` blocks of one epoch may be carried by a block in the next; the
  window does not know epochs. `L`/10 000 of slack at the boundary.
  Not fixed; recorded.

The message gets a **new versioned domain string**; the signature
API's v1 nonce-only domain is not reused, so a v1 signature can
never verify as a v2 one. `verify_pass_countersignature` is a
**consensus** helper (admission of pass records). Changing the signed
message from 32 bytes to `header[72] ‖ shard_id` and carrying the
random plus anchor height is a consensus-rule body replacement,
pre-genesis — named so it is not a silent helper edit.

*Records-was (first amendment, SUPERSEDED the same day, never
landed):* transcript `nonce[32] ‖ height_le[8] ‖ shard_id_le[8]` with
signed height required to **equal** the predecessor height and not
stored. Refuted on two grounds: a requester-chosen integer carries no
existence property (`P` signs blind, so nothing stops a lone witness
pre-fetching for any future height), and exact equality misses every
honest fetch that spans a block boundary.

*LANDED 2026-09-13 by the §9.1 (a0) PR.* Domain string
`shekyl/archival-attestation-scheme-v2` (`SCHEME_DOMAIN_ATTESTATION`,
`shekyl-crypto-pq/src/signature.rs`; v1 retired in
`CRYPTO_DOMAIN_REGISTRY.tsv`, the `archival-attestation-nonce-v1`
cSHAKE customization deleted with `attestation_nonce()`). Helper home
`shekyl-archival-retention::pass_anchor::pass_countersignature_message`
over `pass_request_header_bytes`; `PassRecord` carries
`nonce: [u8; 32]` and `anchor_height: u64`; the prunable witness entry
is `nonce[32] ‖ anchor_height_le[8] ‖ HybridSignature[3385]` and
`attestation_root` commits to `header ‖ nonce ‖ anchor_height ‖
signature`. Verifier input is `predecessor_height` plus the connecting
chain's `L + 1` anchor hashes for `[h − 720 − L, h − 720]`
(`ShekylArchivalAttestationVerifyCtx.anchor_hashes_ptr/len`, filled by
`Blockchain::fill_pass_anchor_window` from the main chain or the alt
chain above the fork point; `cb_out_key`, `cb_out_key_readable`,
`prev_block_hash` removed; verdicts 8 and 12 RETIRED; new verdicts 13
`MALFORMED_ANCHOR_TABLE`, 14 `ANCHOR_OUT_OF_WINDOW`, 15
`BELOW_ANCHOR_THRESHOLD`; C++ sizes the table via
`shekyl_archival_pass_anchor_window`). Witness cap
`ATTESTATION_WITNESS_MAX_BYTES = 876 808` (+40/entry versus v1),
Rust-authoritative, C++ asserted equal. Pinned vector (rule-50 tier 3, a
drift tripwire — the hand-computed header/transcript concatenations are the
KATs): a deterministic fixture
(`tests/fixtures/attestation_pass_countersignature_v2_pinned.json`, keys
from `derive_archival_p_keys` at a pinned seed, a deterministic
`pinned_chain_hash` window) shared by the Rust, FFI, and C++ tests,
regenerated under the armed regenerator with the decision-log entry of
2026-09-13. The `P`-side gate and header parse are (a)'s.

**Response carrier — RULED 2026-09-13; LANDED by (a)+(b)
(`SIGNATURE_ENVELOPE_LEN` on both ends).** `RF-D4`'s
`ServedFrameHeader` contains only `leaf_count` and `padding_len` and
the pre-(a) HTTP response carried no countersignature, so the signature
needed a home that is neither the inner frame nor a header:

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
  length field and the frame offset is a constant. The client **reads
  exactly `signature_envelope_len` bytes, then parses**. It does not
  stream-parse `HybridSignature` by trusting the inner `u32` length
  fields. The serve crate obtains the signature from the `SF-D13`
  callback; it does not load the secret.
- **Verify placement:** inside the fetch call. The client returns only
  verified-or-refused, never raw bytes — a raw-bytes return invites a
  caller to skip either check. The successful type carries the
  verified shard and the signature; parse, `RootMismatch`, and
  `BadCountersignature` are its three typed refusals.
- **Reopen if:** the reconstruct caller demonstrates a need for an
  unverified stream (for example partial-segment resume) that cannot
  be met behind the seam. The fixed-width envelope read is the
  rule-76 answer; it is not a reopen.

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
drawable snapshot (`DrawableSet::at_epoch_open`, SO-D8 Q3 RULED 2026-09-16),
performed by the **organic scheduler**. Per-need
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
   list is the thing this ruling refuses. **The set lives exactly as
   long as the need does, and the need's lifetime is `TJ-D`'s.** A
   need that backs off and retries for hours carries an hours-long
   exclusion set, which is the edge of "scratch." So the `client-need`
   handoff hands `TJ-D` a privacy-relevant bound, not only a
   scheduling one: how long a need lives is also how long a daemon
   remembers which `P`s it has already tried for `s`, and it is not to
   be set on fill-throughput grounds alone.
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
`SF-D6` taxonomy row plus per-need exclusion is the entire behavioral
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
   callers send requester-random plus the same deterministic chain
   anchor at `tip − 720`.
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
   handoff.** The serve-side limiter is load-bearing
   (`shekyl-p-serve::serve::MAX_INFLIGHT`; `EU-D6` is REJECTED but the
   limiter is code). The
   form that would slash is a third party keeping an *honest* `P`'s
   assigned challenge fetches from landing; the honest holder did
   nothing wrong. A full limiter is **not** a 404: `RF-R1` closes
   over-capacity arrivals with no HTTP bytes, which this table files
   as stall-class — bounded retries, then a challenge **miss**.
   Darkness and a full limiter look the same to the client (silent
   close). An honest `P` at cap is therefore on the slash path after
   retries. **Nothing this client can do is the defense,** and
   **nothing this round owes the challenge mechanism.** Volumetric
   denial over onion is symmetrically priced and untargetable; the
   cheap attack is positional and already owned.

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
   `MAX_INFLIGHT`. Sustain is the binding constraint: occupy most of the
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
   parameters, (2) the service's own stream limiter (`MAX_INFLIGHT` /
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
- The `EU` landing sequence — **VOID 2026-09-13.** A landed (#712);
  B+C1's JoinMarket half landed (`b5578d885`, `BondPost.endpoint`,
  LMDB v13); its kind-4 half and D (the `hs_id` rotation index) were
  REJECTED with `EndpointUpdate` (`EU` §5; archive tags
  `archive/feat/eu-b-c1-endpoint-update-wire-2026-09-13`,
  `archive/feat/eu-d-hs-id-rotation-2026-09-13`). D has no carrier
  because it has no consumer: the endpoint is immutable, so there is
  nothing to rotate to. REJECTED, not deferred — zero FOLLOWUPS rows
  (rule 23); the only surviving debt is the `ARCHIVAL_P_DERIVE_V1`
  regenerator-arming row, already in FOLLOWUPS.
- Vin-carried opening deletion (TJ-1 closer; a consensus cutover, not
  this client).
- W₂ numeric pin — **LANDED 2026-09-16** as §9.1 (c) on PR #746:
  `shekyl_p_fetch::MAX_INFLIGHT = 8`. Serve-side SPIKE-PIN-1/2 stay
  where `SF-D7` left them.
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
`nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]` — requester-random
and the chain anchor at `tip − 720`, both callers, gated ±`L` by `P`
against its own height; `SF-D5` RULED and amended),
one failure taxonomy with two caller columns (`SF-D6` RULED: per-attempt
handling is the client's; 404 is a completed exchange; no-endpoint is
unrepresentable since the `EU` kind-4 rejection of 2026-09-13, so the
former non-row is void; organic draw bound `k` is `TJ-D`'s;
`content-length` equals the
constant signature-envelope length plus inner `framed_len()`, with
disagreement known before segment bytes; parse, root mismatch, and bad
countersignature are typed separately), one fixed client
in-flight cap and one shared admission path (`SF-D7` RULED, amended:
`fetch(&FetchTarget, &header, verifier)` with the target typed —
`ServingEndpoint`, `HybridPublicKey`, `u64` — expected content in the
per-call `ContentVerify` hole until `PDM-Q6`;
caller-supplied from local chain state, never from a response; integer
pinned by the implementation PR from SP-T3's upper bound and its own
lower-bound throughput judgement), the stable bond-record hybrid
identity signing key (`SF-D13`: callback into `PServeEndpoint`; crate
holds no secret; the host also supplies `P`'s height), the signed
message `header[72] ‖ shard_id_le[8]` under
`shekyl/archival-attestation-scheme-v2` (challenge tuple not in the
fetch; pass record carries the random and the anchor height; admission
looks the anchor hash up on the connecting chain inside
`[h − 720 − L, h − 720]`), the outer
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

### 9.1 Landing sequence — fixed 2026-09-13

One PR was over the rule-06 ceiling and mixed a consensus verifier
change with HTTP framing. Four PRs, each green alone, in this order:

- **(a0) the v2 pass-countersignature verifier, first and alone —
  LANDED 2026-09-13** (branch `feat/sf-a0-v2-pass-countersignature`;
  PR number recorded in the index row at merge).
  `verify_pass_countersignature` re-anchored to
  `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8]`
  under the new versioned domain string, taking the connecting chain's
  anchor window across the FFI (one indexed lookup; alt-chain fill
  above the fork point; genesis threshold 724 with KATs at 723/724),
  constants single-sourced from `consensus_constants.json`
  (`archival_reorg_depth_blocks` reused as depth, new
  `archival_attestation_anchor_lag_blocks = 4` PROVISIONAL), with its
  KAT regenerated under an armed regenerator and the decision-log
  entry rule 50 requires. This is a consensus verifier change: it
  lands on its own (rule 07 shape), not inside a serve-side HTTP PR.
  `SM-R-3` is live the moment `P` signs caller-chosen bytes, so a
  defect in the domain-separation construction surfaces here, before
  anything depends on it.
- **(a) serve side — BUILT 2026-09-13 (commits `0ed3e11e0`,
  `1a0ea3e90`, `64a81697a` of the sub-PR 1 branch).** `RF-R1` header parse (one required header
  decoding to the 72 bytes, same identical 404 on
  absence/malformation/out-of-gate), the `P`-side anchor gate ±`L`
  against the host-supplied height, signing over the **decoded**
  bytes, the fixed-length
  `HybridSignature` envelope ahead of the unchanged `RF-D4` frame, the
  `PServeEndpoint` signer callback with the armed test-key affordance
  (`SF-D13`), and the `RF-R1` living-contract update. Its loopback KAT
  verifies against the verifier (a0) already merged.
- **(b) `shekyl-p-fetch` — BUILT 2026-09-13 (`62076d69c`, `5f553754a`).**
  The client, `FetchTarget` (`SF-D7` amendment) and the
  `ServingEndpoint` newtype in `shekyl-p-fetch` (onion hostname from
  `shekyl-onion-v3`), the `SF-D6`
  taxonomy as typed errors, the dep-cut gate
  (`check_p_fetch_dep_cut.py`), and SPIKE-PIN `N = 4` with its
  lower-bound rationale recorded.

  **Amendment 2026-09-13 — (a) and (b) land as one PR.** The
  FOLLOWUPS row (the implementation record) already scoped them as one
  sub-PR, and (a) alone would merge a server requiring a header no
  client in the tree sends. Seven scope-respecting commits in the
  (a)→(b) order, stacked on #734 because the client compiles against
  (a0)'s `pass_anchor`; under the rule-06 ceiling. The stacked PR's
  description carries this disclosure.
- **(c) W₂ on (b), then pin `N` — LANDED 2026-09-16 (PR #746).** The
  SP-T3 daemon→wallet re-base runs against the (b) client — and
  **re-based the rig's client leg onto it**: `shekyl-p-transport::blocking_get`
  cannot carry the `SF-D5` header. Topology: one client tor the fetches
  dial through with no per-fetch isolation (the production posture),
  each persona behind its own tor. "Cold" is `SIGNAL NEWNYM` on the
  client tor; "warm" is circuit reuse. `live_apparatus` passed over
  real Tor (user shell, 51 s). Fixture: shard-0, 3 326 976 bytes
  (served body 3 326 980). Endpoints served 3 642, shed 0.

  | Arm | n | ok | p50 | p99 | D* |
  |---|---|---|---|---|---|
  | Cold (`NEWNYM`) | 200 | 99.0% | 11.31 s | **48.27 s** | 17.74 s |
  | Warm | 200 | 99.5% | 5.09 s | 12.26 s | 6.96 s |
  | Soak ≥24 h | 1774 | 98.0% | 13.43 s | **86.06 s** | 28.13 s |

  Churn (all valid, 0 VOID rows, 0 cap sheds): w1 n=100 p50=12.41 s
  p99=32.60 s circ 0%; w2 n=200 p50=11.36 s p99=57.50 s circ 1.0%;
  w4 n=400 p50=11.53 s p99=50.09 s circ 0%; w8 n=800 p50=13.21 s
  p99=57.16 s circ 0% mem 53.2 MB. Pin
  `N = min(largest non-churning width, Pi 4 memory) = 8`. Memory
  does not bind. 16 was not measured.

  **`L` verdict (printed, not pinned):** DROP-TO-3 CANDIDATE
  (cold p99 48.3 s < 120 s); 7 attempts of that p99 fit under 6 min.
  Soak p99 86 s still < 120 s — does not walk the candidate back,
  still not fetch-plus-retry. `archival_attestation_anchor_lag_blocks`
  stays 4. No further tests required for (c).

The round doc stays in `docs/design/` while `L` is PROVISIONAL and
Sub-PR 2 / SH-2 remain (the "archive when (c) lands" criterion
expired 2026-09-16).

## 10. What this round did not find

Surfaces examined that did not yield a further disposition:

- A non-default virt-port as an anti-enumeration lever (`SF-D5`
  reopen only).
- Copying `IsolateSOCKSAuth` onto the daemon fetcher (`SF-D3`).
- A second Tor process (`SF-D2`).
- Verify-failure as a selection input (`SF-D12`).
- A leaf-addressed suffix as a Round-1 path (`SF-D1` holds that door
  shut).
- Serving and fetching sharing a Tor instance (`SF-D11` withdrawn;
  `PWD-E9`).

The nonce-as-challenge-fingerprint was a **finding**, not a clean
surface: putting `attestation_nonce` on the wire would have named the
assignment. Ruled off the fetch (`SF-D5`/`SF-D8` amendment).
Same-height reuse of a signature across competing blocks was examined
and accepted: the fetch proves `P` served — and the anchor is buried
720 deep precisely so that reuse survives a same-height race (a
tip-hash anchor would have lost it). The first amendment's
requester-chosen height-only transcript was examined the same day and
SUPERSEDED before landing: it carried no existence property.
