# Archival serving route — request contract

**Status: LIVING CONTRACT.** Ruled 2026-09-10 (`RF-R1`). Last verified
2026-09-12 (`SF-D9`: topology is daemon→P per `EU-D1`).

This is the request half that
[`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md)
(`RF-D1`…`RF-D10`) and
[`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §9.5
both declined. Those exclusions stand: this is not a format-round
document and not consensus. It is the HTTP/1.1-over-onion request a
witness uses to fetch a shard. Index row `RF-R1`. Implementation:
`rust/shekyl-p-serve` (`ROUTE_PREFIX`, `parse_request`,
`RESPONSE_HEADER_NAMES`, `NOT_FOUND`).

The body after `\r\n\r\n` is `RF-D4`
(`shekyl_curve_tree::served_frame::ServedFrameHeader`). This document
does not own it.

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

Today none of the three has fired: there is no production fetcher
(`RF-D4`), and `PersonaServingHost` has never published a descriptor
(index SH-1 / SH-2b-2 remainder). The ruling still lands now because
genesis software will ship this path, and silence is how
`/x-provisional/v0/shard/` would have shipped.

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
Until that reopening, anything other than `/shard/{id}` is the shared
404.

The discarded path is a miss, same as any other wrong path. Do not keep
it as an alias.

### Status and headers — RULED by transcription

Transcribed from `shekyl-p-serve`, pinned by
`two_personas_are_header_identical` and
`every_non_servable_outcome_renders_one_identical_404`. Do not redesign;
the tests are the spec.

- Success: `HTTP/1.1 200 OK`, headers exactly
  `RESPONSE_HEADER_NAMES` = `content-type`, `content-length`, nothing
  else. No `date`, no `server`, no `etag`, no `accept-ranges`.
- `content-type` is `application/octet-stream`.
- Every **complete-head** non-servable outcome — wrong path, wrong
  method, malformed route/id, unknown shard, unfrozen shard, store
  failure — renders one identical 404 with the same two headers and
  `content-length: 0`.
- Incomplete heads (oversized, mid-head EOF, read timeout) and
  over-capacity arrivals are **closed with no HTTP bytes**.
- Which response a complete head gets is settled before any byte is
  written.
- No request logging at any level. Observables are four aggregate
  monotone counters (served, refused, lookup failures, accept failures).

Two personas served from one wallet are byte-indistinguishable at the
header level. That is the privacy invariant
([`00-mission`](../../.cursor/rules/00-mission.mdc) commitment 2).

### Request grammar — RULED by transcription

`parse_request` in `shekyl-p-serve/src/serve.rs`:

- Method is exactly `GET`. Anything else is a miss.
- A request-line version token must be present; its **value is not
  discriminated** (`HTTP/1.0` and `HTTP/1.1` take the same path). Extra
  tokens after it are a miss.
- `{id}` is an exact decimal `u64` (`FromStr`). No path suffix, no query
  string, no sign. Leading zeros are accepted by `u64` parse (so `/shard/007`
  is shard 7); that is current behaviour, not a second encoding.
- Request headers are ignored. Presence, absence, and values are not a
  discriminator.

### Transport — RULED by transcription

HTTP/1.1, hand-rolled, because a framework's default `date` / `server`
headers are the fingerprint this contract forbids. The endpoint binds
`127.0.0.1:0` only; reachability is the `ADD_ONION` mapping
`shekyl-p-host` wires. This crate does not speak Tor.

`MAX_INFLIGHT`, `MAX_REQUEST_BYTES`, and the write/stall timeouts are
**not** this contract. `MAX_INFLIGHT` remains SPIKE-PIN-2 (a placeholder
the W₂ rig derives). They are operational bounds, not the request line.

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

---

## Falsifier

**Holds** iff `ROUTE_PREFIX == "/shard/"` in
`rust/shekyl-p-serve/src/serve.rs` and
`request_parsing_accepts_only_the_ruled_route` is green (the discarded
`/x-provisional/v0/shard/` path is a miss).

**Broken** iff `ROUTE_PREFIX` contains `provisional` or `v0`, or the
discarded path is accepted.

The loud form of failure is either string surviving into a genesis-freeze
tag as the live prefix.
