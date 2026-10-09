# Archival serving route — request contract

**Status: LIVING CONTRACT.** Ruled 2026-09-10 (`RF-R1`). Last verified
2026-10-06 (five answers: a bare 400 for an invalid request, decided
ahead of the shard lookup; a bare 404 that means not held and nothing
else; a bare 503 for a fault of `P`'s own; a good read; and a refusal
trailer when the signer fails after the body. `P` reads a shard once and
signs after sending it; the
countersignature envelope **closes** the body and signs a nonce-salted
digest of it — `SF-D8`; request
header the 2026-09-13 (a)+(b) landing; client
`shekyl_p_fetch::MAX_INFLIGHT = 8` W₂ pin; grammar homed in
`shekyl_curve_tree::serving_route`).

This is the request half that
[`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md)
(`RF-D1`…`RF-D10`) and
[`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §9.5
both declined. Those exclusions stand: this is not a format-round
document and not consensus. It is the HTTP/1.1-over-onion request a
witness uses to fetch a shard. Index row `RF-R1`. Implementation: the
grammar both ends read is `shekyl_curve_tree::serving_route`
(`SERVING_VIRTUAL_PORT`, `ROUTE_PREFIX`, `CONTENT_TYPE`,
`RESPONSE_HEADER_NAMES`, `REQUEST_HEADER_NAME`,
`encode_request_header` / `decode_request_header`);
the server is `rust/shekyl-p-serve` (`parse_request`, `resolve_body`,
`render_not_found`); the client is `rust/shekyl-p-fetch` (`PFetchClient`,
`RequestHeader`, `ServingEndpoint`, `FetchError`). The onion hostname is
not route grammar: `shekyl-onion-v3` is the one rend-spec transform,
typed on the daemon as `ServingEndpoint` and on the wallet as
`OnionIdentity` (`PWD-E9`).

The body after `\r\n\r\n` is the shard body then the
**countersignature envelope**: the provider's bytes, unframed by the
serve loop (the `SHT-Q2` tx-range body in `shekyl_wire::shard_frame`,
`SF-D8` as amended 2026-10-08; ~~the `RF-D4`
`shekyl_curve_tree::served_frame::ServedFrameHeader` ‖ payload~~, retired
the same day) ‖ `HybridSignature` canonical bytes
(`SIGNATURE_ENVELOPE_LEN = HybridSignature::CANONICAL_LEN`, 3385)
(`SF-D8`). The envelope is the response's last bytes: the signed
transcript includes a digest of every body byte ahead of it, salted with
the request's nonce. This document owns the envelope's *position and
width*; the signature's transcript is `SF-D8`'s and the frame is
`RF-D4`'s.

---

## Freeze clock

This is a daemon→P serving protocol — the client is a daemon, the
server is a P-served onion; no wallet talks to a wallet (`EU-D1`,
[`ARCHIVAL_ENDPOINT_UPDATE.md`](ARCHIVAL_ENDPOINT_UPDATE.md), ruled
2026-09-11) — not a consensus wire.
Changing it after the freeze is a coordinated software upgrade
([rule 75](../../.cursor/rules/75-system-autonomy.mdc)), not a hard fork
([rule 42](../../.cursor/rules/42-serialization-policy.mdc) does not
fire; `RF-D4` already checked this class of artifact).

The contract freezes at the **earliest** of:

1. a production fetcher exists that speaks it
2. a `PersonaServingHost` has published a real onion descriptor
3. genesis software is tagged

Until then the path is still cheap to change. After, it is a flag day.

Today none of the three has fired — but (1) is one wiring away. The
client crate `shekyl-p-fetch` speaks this contract (`SF` (b),
2026-09-13); no daemon path invokes it yet (the challenge / reconstruct
scheduler is `SF` sub-PR 2's, behind `PDM-Q6`). `PersonaServingHost`
has never published a descriptor (index SH-1 / SH-2b-2 remainder). The
ruling still lands now because genesis software will ship this path,
and silence is how `/x-provisional/v0/shard/` would have shipped.

---

## Four pieces

### Path — RULED `/shard/{id}`

`GET /shard/{id}`. `ROUTE_PREFIX = "/shard/"`.

Was `/x-provisional/v0/shard/`. Discarded because:

- `provisional` as a frozen label is a lie
- `v0` is a version token with no `v1` — a reserved slot
  ([rule 21](../../.cursor/rules/21-reversion-clause-discipline.mdc))
- `x-` is the unofficial-prefix convention

The onion serves one resource. The path names it. Genesis stays
`GET /shard/{id}`. If a later request contract is needed, it is an
**additional** path that suffixes `/shard/` (the resource name stays; a
token is added), with a named reopening — not a rename of this path, and
not a `v0` slot reserved today
([rule 21](../../.cursor/rules/21-reversion-clause-discipline.mdc)).
Until that reopening, anything other than `/shard/{id}` is an invalid
request: the bare 400.

The discarded path is invalid, same as any other wrong path. Do not keep
it as an alias.

### Status and headers — RULED by transcription

Transcribed from `shekyl-p-serve`, pinned by
`two_personas_are_header_identical`,
`every_invalid_request_is_the_one_bare_400_held_or_not`,
`only_a_valid_request_for_an_unheld_shard_is_the_404` and
`a_persona_with_no_key_answers_503_and_sends_no_shard`. Do not redesign;
the tests are the spec.

A complete head gets one of five answers, and a failure shows as a
failure: a held shard never answers 404, and `P` failing is never
inferred from a response that stopped.

| Response | Meaning |
| --- | --- |
| `400`, empty | The request is invalid. Decided from the head and `P`'s own height, with no shard lookup and no branch on holdings. |
| `404`, empty | Not held. Only a valid request reaches this, and nothing else does. |
| `503`, empty | `P` cannot serve right now and the fault is its own: an unreadable tip, a store failure, or no resident key. |
| `200`, body, signature | A good read. |
| `200`, body, refusal trailer | `P`'s signer failed after the body went out. |

Holdings are chain-public, so none of the three bare codes reveals
anything a requester could not already learn. A 404 for a bonded shard
would say "not held" of a shard the chain says is held.

- Success: `HTTP/1.1 200 OK`, headers exactly
  `RESPONSE_HEADER_NAMES` = `content-type`, `content-length`, nothing
  else. No `date`, no `server`, no `etag`, no `accept-ranges`.
- `content-type` is `application/octet-stream`.
- The three bare answers carry the same two headers and
  `content-length: 0`, and each is one fixed byte string. Nothing in the
  400 names the check that refused; nothing in the 503 names the fault.
- **400.** Every **complete-head** request that is not valid — wrong
  path, wrong method, malformed route/id, missing / duplicate /
  malformed / wrong-length request header, `anchor_height` outside
  `P`'s gate. The same whether or not `P` holds the shard.
- **404.** A valid request for a shard `P` does not hold: unknown or
  unfrozen.
- **503.** A valid request `P` cannot serve through its own fault: the
  tip the gate needs could not be read, the store failed to open the
  shard, or no key is resident. The keyless case is decided before the
  body, so no shard is sent only to go uncountersigned.
- On 200, `content-length` is `framed_len + SIGNATURE_ENVELOPE_LEN`,
  and a 200 that completes is exactly that long. The body is the
  `RF-D4` frame, then an envelope of the signature's width. `P` reads
  the shard once, hashes each chunk as it sends it, then finishes the
  digest, signs, and writes the signature as the envelope.
- **The refusal trailer.** If the signer fails after the body, the
  envelope is `REFUSAL_TRAILER_BYTE` (`0xFF`) repeated across its width
  (`serving_route::is_refusal_trailer`). It cannot parse as a canonical
  `HybridSignature`. `P` says in its own bytes that it served and did not
  sign.
- **A 200 that stops short is transport, at every offset.** A relay can
  cut a stream where it likes, the frame's end included, and guard
  pinning puts the same relay on every retry; it cannot write into an
  onion-service stream. So only the trailer means `P` refused, and a
  cut is a stall the requester retries.
- **One response, then close.** `P` shuts its write half as soon as
  the last body byte is written (`close_gracefully`), so the client's
  EOF is behind the body, not behind a keep-alive. The client reads
  exactly `content-length` bytes and then **requires** that EOF: bytes
  instead are `SF-D6` overlength (malformed), silence instead is a
  stall (`Stall::NoClose`). A 400, a 404 and a 503 are held to the same
  standard — a "no" with bytes behind it is not the bare answer.
- Incomplete heads (oversized, mid-head EOF, read timeout) and
  over-capacity arrivals are **closed with no HTTP bytes**.
- Whether a complete head gets the 400, the 404, the 503 or a 200 is
  settled before any byte is written. The request is judged **before**
  the shard lookup, and the signature is computed **after** the body is
  sent, so an invalid request costs no store read and a 404 costs no
  signature.
- No request logging at any level. Observables are five aggregate
  monotone counters (served, refused, lookup failures, sign failures,
  accept failures).

Two personas served from one wallet are byte-indistinguishable at the
header level. That is the privacy invariant
([`00-mission`](../../.cursor/rules/00-mission.mdc) commitment 2).

### Request grammar — RULED by transcription

`parse_request` in `shekyl-p-serve/src/serve.rs`:

- Method is exactly `GET`. Anything else is invalid (the 400).
- A request-line version token must be present; its **value is not
  discriminated** (`HTTP/1.0` and `HTTP/1.1` take the same path). Extra
  tokens after it are invalid.
- `{id}` is an exact decimal `u64` (`FromStr`). No path suffix, no query
  string, no sign. Leading zeros are accepted by `u64` parse (so `/shard/007`
  is shard 7); that is current behaviour, not a second encoding.
- **One required request header** (`SF-D5`, second amendment, LANDED
  2026-09-13 as `SF` (a)): name `shekyl-pass-request`
  (`REQUEST_HEADER_NAME`; matched case-insensitively, as HTTP names
  are), value the **lowercase hex** of exactly 72 bytes
  `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`
  (`REQUEST_HEADER_BYTES`; `encode_request_header` /
  `decode_request_header`). The value is strict: 144 lowercase hex
  digits, optional surrounding whitespace only. Missing, duplicate,
  uppercase, wrong-length, or non-hex values are the bare
  complete-head 400, and so is an `anchor_height` outside
  `[p − 720 − L, p − 720 + L]` for `P`'s own height `p`
  (`L = archival_attestation_anchor_lag_blocks`, the same `L` on both
  sides so no `P` gates distinctively). For `p < 720` there is no
  anchor at depth 720 yet and `P` refuses every request; for
  `720 ≤ p < 720 + L` the window's lower edge clamps at height 0
  (`anchor_within_gate`, `shekyl-p-serve`). `P` signs the **decoded**
  72 bytes ‖ `shard_id_le[8]` ‖ `delivery_digest[32]`
  under `SCHEME_DOMAIN_ATTESTATION` (`SF-D8`;
  `shekyl_archival_retention::pass_anchor::pass_countersignature_message`),
  never the textual form. Every other request header is ignored.
- The client sends exactly two lines after the request line: the
  header above and the blank terminator. No `host`, no `user-agent`,
  no `accept` — every requester's head is byte-identical modulo `{id}`
  and the header value (`SF-D1`, requester side).

### Transport — RULED by transcription

HTTP/1.1, hand-rolled, because a framework's default `date` / `server`
headers are the fingerprint this contract forbids. The endpoint binds
`127.0.0.1:0` only; reachability is the `ADD_ONION` mapping
`shekyl-p-host` wires. This crate does not speak Tor.

`MAX_INFLIGHT`, `MAX_REQUEST_BYTES`, and the write/stall timeouts are
**not** this contract, on either end. The server's `MAX_INFLIGHT`
remains SPIKE-PIN-2 (a placeholder the W₂ rig derives); the client's
`shekyl_p_fetch::MAX_INFLIGHT = 8` is `SF-D7`'s W₂ pin (`ARCHIVAL_SHARD_FETCH.md`
§9.1 (c), 2026-09-16); `shekyl_p_fetch::Timeouts` and
`max_body_bytes()` are operational bounds. They decide when an attempt
is a stall or a refusal, never what a completed exchange means.

The client dials `shekyl_p_fetch::ServingEndpoint::onion_address():80` through the
daemon's own Tor client as SOCKS5**h** (`SF-D2`, `SF-D3`): the proxy
resolves the name; the client resolves nothing and offers no SOCKS
auth (no per-fetch circuit isolation).

---

## What this is not

- Not the served body (`RF-D4`).
- Not a vote in the format round. §9.5's exclusion stands; this is the
  successor that exclusion lacked.
- Not a promise that HTTP/1.1 remains the serving transport after a
  future serving redesign. A successor transport is a new contract with
  a named reopening, not a version bump of this path.
- Not a reserved `/v2/shard/` (or any other token) in today's route
  table. The suffix-shaped successor is the reopening *shape*, not a
  path this endpoint answers.
- Not a path the **daemon** answers, now or under any performance
  argument. The serving path runs from the wallet-side shard store; the
  daemon holds archival consensus state and no serving state, because an
  archiver-backed daemon that behaves differently from a plain one
  fingerprints the Principal's public address (RULED 2026-09-17,
  `V3_WALLET_DECISION_LOG.md`, two stores). **As built today** the route
  serves 128-byte leaf bytes (consensus already: the leaf-hash preimage,
  PL-D3 frozen) under the leaf partition (`frozen_segment_count` decides
  admissible `shard_id`s and what pop revert deletes; the
  `SEGMENT_LEAF_COUNT` ↔ `shekyl_curve_tree::segment` tie is an interim
  FOLLOWUPS row). **Under `PDM-Q6` item 4 (RULED 2026-09-18, #774; re-keyed
  here 2026-09-18, `PDM-Q-F33`)** the served frame becomes per-tx prunable
  bodies keyed by `[b_k, b_{k+1})`, and what the two independently built
  stores must agree on is the **shard partition `b_*`** — consensus,
  derived only from the daemon's retained length rows (F32) with
  `SHARD_BYTES` in one const-asserted home; the leaf partition and its
  tie are a deletion surface at E4 / S-ARCH (Q12). The archiver-store
  retention horizon is a FOLLOWUPS row under either unit.
  A daemon *fetching* a shard through this route for its own reasons is
  episodic and carries no posture signal; *serving* would be durable, and
  that is the distinction the ruling rests on.

---

## Falsifier

**Holds** iff `ROUTE_PREFIX == "/shard/"` in
`rust/shekyl-curve-tree/src/serving_route.rs` and
`request_parsing_accepts_only_the_ruled_route` is green (the discarded
`/x-provisional/v0/shard/` path is invalid); and the two ends agree on
the header and the envelope —
`request_header_parsing_is_http_lenient_and_value_strict` and
`the_served_body_is_the_frame_then_the_countersignature` and
`the_countersignature_is_released_only_after_the_whole_frame` and
`a_signer_that_fails_after_the_body_closes_it_with_the_refusal_trailer`
(`shekyl-p-serve`) green beside
`garbage_with_a_valid_signature_appended_is_refused`,
`a_signature_sent_ahead_of_the_body_is_refused`,
`a_body_closed_with_the_refusal_trailer_is_a_failed_read`,
`a_good_response_cut_exactly_at_the_frames_end_is_a_stall`,
`a_503_is_a_failed_read_with_no_retry` and
`a_400_is_rejected_and_earns_one_retry_with_a_fresh_anchor`
(`shekyl-p-fetch`), the cross-stack
`the_bare_answers_and_a_good_read_reach_the_client_as_typed_outcomes`
(`shekyl-p-fetch/tests/against_serve.rs`), and
`a_signed_shard_comes_back_verified_and_the_proxy_got_the_onion_name`
(`shekyl-p-fetch`), which pins the client's request bytes verbatim.

**Broken** iff `ROUTE_PREFIX` contains `provisional` or `v0`, the
discarded path is accepted, or either end reads the grammar from a
constant that is not `serving_route`'s (`scripts/ci/check_p_fetch_dep_cut.py`
holds that the client reaches `shekyl-curve-tree`; a re-spelled
constant is the review's catch).

The loud form of failure is either string surviving into a genesis-freeze
tag as the live prefix.
