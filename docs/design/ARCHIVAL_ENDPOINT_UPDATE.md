# `EndpointUpdate` — the round record (EU)

**Status:** **REJECTED** (kind 4) — Rick, 2026-09-13. A bonded persona's
endpoint never changes; a new onion address is a new persona, reached by
Release and a fresh `JoinMarket`. Three of the round's dispositions survive as
the **JoinMarket-endpoint design** — `EU-D1` (the daemon is the client),
`EU-D3` (the endpoint field, on `JoinMarket` only), `EU-D4` (the witness reads
it from the drawable snapshot through the record) — and land in the
JoinMarket-endpoint PR (number filled in on landing). Everything else in the
round (`EU-D2`, `EU-D5`…`EU-D13`, the 2026-08-10 "carrier ruling" they
implemented, and the `ARCHIVAL_P_DERIVE_V1` retirement authorized for D) is
rejected with it — §5. **Read §1 before reasoning about endpoints.**

**Identifier family** `EU-`, registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2; the rejected
dispositions keep their numbers so citations resolve to a REJECTED line
([rule 23](../../.cursor/rules/23-disposition-visibility.mdc)).

**Decision authority:** Rick.

---

## 1. The ruling — 2026-09-13

**In Rick's words, verbatim:**

> "IT has always been - who said it could rotate? That is a HARD NO. Rotating
> an existing bond is a dead giveaway for someone to link it. IT has been the
> rule for a long time. THe roation COULD be about a daemon, but how the fuck
> would you lose the key if it's derived from the seed?"

**What it fixes.** The persona's serving identity (`hs_id_seed`) is an HKDF
child of the persona slot, exactly like its identity and bond-spend keys: one
onion per persona is the design, not a gap. The "endpoint-burn" cases the
rejected carrier paragraph priced do not survive grounding:

- *Lost onion key* — cannot happen; the key is re-derived from the seed.
- *Discovered address* — the address is published in the `JoinMarket` post
  and dialed by every witness. Public is its normal state.
- *Compromised host* — the attacker holds the serving seed and the identity
  signing key. No endpoint change takes either back, and posting one adds a
  public, timestamped record that this persona moved, correlated with the
  operator's own incident. The one act that ends the attacker's position is
  Release, authorized by the one key never on the host (`bond_spend_pk`,
  principal-tier custody — C0, PR #703); the operator then joins from a
  clean box as a new persona.

**What it does not touch.** The daemon's own onion address (network posture)
is a different object, not on chain, and not this record's subject.

---

## 2. `EU-D1` — RULED 2026-09-11: the daemon is the client; no wallet talks to a wallet

**In Rick's words:**

> "From the typical coin perspective, the wallet is the client of the daemon
> in that the daemon is doing the p2p work and maintaining the blockchain
> state. However, from the ARCHIVAL perspective, the daemon would be a client
> of a remote wallet serving P so that it could check shards, verify a
> challenge, etc. But this is a special case, whereas the wallet is a client
> of the daemon is the typical case. **In no case should one wallet talk to
> another.** RPC is a separate layer on top of that base relationship."

**What it settles, and why it was already true.** Fork 2 of the challenge
mechanism (CLOSED 2026-08-10) made the witness *the producer of block h* —
"miners are the only population where being selected *is* proof of being
online at that instant" — and §9.4 says "miners are simply clients of it."
Miners run daemons. `EU-D1` ratifies at the architecture level what the
mechanism round forced at the selection level; nothing reopens. The
no-wallet-to-wallet clause is **satisfied by construction**: the only party
ever drawn is whoever produced block *h*, and there is no oracle for anyone
else's liveness to draw on instead.

**Consequences this round carries forward:**

1. **Discovery is a chain read.** The daemon already holds the chain, so
   "which persona holds shard *s*, and where is it" is a local lookup against
   the bond record — no gossip layer, no DHT, no new Levin message. That is
   the whole simplification the boundary buys, and it is why the endpoint
   lives on the record (`EU-D3`, `EU-D4`).
2. **The shard route stays HTTP-over-onion, not a P2P message.** The server is
   a wallet (`shekyl-p-host` / `shekyl-p-serve`), not a peer node; a daemon
   P2P message would make the wallet a P2P participant, which the boundary
   forbids in the other direction.
3. **The fetcher is a daemon subsystem, written in Rust** beside
   `shekyl-daemon-rpc` (rule 20; the countermand), reaching personas over the
   daemon's Tor surface. `shekyl-tor-control-daemon` is the crate that exists
   there; that it carries *outbound* is TJ-B's to confirm, not this round's
   claim. Out of this round's scope — TJ-B's — but its home is fixed here.
4. **SP-T3 measured the wrong topology.** The dispersion spike is
   persona→persona onion; the protocol path is daemon→wallet. **Obligation on
   TJ-B, not an `EU-` disposition:** re-base the measurement daemon→wallet
   *before* promoting SP-T3 to challenge substrate, or W₂ is derived from a
   topology the protocol never uses. The index already notes the adjacent
   hazard (a single daemon makes both ends share a guard).
5. **RPC is a separate layer.** The shard fetch is not a wallet-RPC method and
   not a daemon JSON-RPC method; it is a daemon-initiated outbound fetch. The
   `-29505` refusal and its siblings live at the RPC layer and are not where
   this is solved.

---

## 3. `EU-D3` — RULED 2026-09-11, narrowed 2026-09-13: the endpoint is the raw 32-byte Ed25519 key, present iff `JoinMarket`, mandatory there, immutable for the record's life

**Encoding.** The v3 onion address is `pubkey ‖ checksum ‖ version`,
base32-encoded — everything but the key is derived. Storing the string would
put a parser and a canonicalization question on a genesis-frozen surface,
cost 56 bytes for 32 bytes of entropy, and admit non-canonical spellings that
differ as bytes and agree as addresses. Rule
[65](../../.cursor/rules/65-address-format-discipline.mdc) (an address is a
display form over a key) points at the key, and so does rule
[42](../../.cursor/rules/42-serialization-policy.mdc) where it applies — the
**wallet's** persisted copy of the field (Freezes, above), not the vin: a fixed
32-byte field versions cleanly; a string carries a format question into every
version bump.
**The address is a display form.** A reader reconstructs it; the wire never
carries it.

**Presence.** Present iff `post_kind == JoinMarket` — the same condition as
`bond_spend_pk`, so the two fields share one coupling branch in `write` /
`read_payload`. A `JoinMarket` vin without an endpoint, or a `Release` /
`Rebond` / `HoldingsUpdate` vin with one, is unrepresentable on the wire, the
same idiom as the amount arms. An all-zero endpoint on `JoinMarket` is refused
by consensus on both sides, because the daemon's flat vin struct represents
"absent" as the zero key and cannot tell the two apart.

**Mandatory on `JoinMarket`.** The carrier ruling's *"a bond without an
endpoint was the discovery gap"* reads as mandatory; it lands as a
non-`Option` field. There is no chain and no wallet, so there is no legacy
bond to accommodate — a bond without an endpoint cannot be constructed.

**On the record.** `ArchivalBondValue` gains a 32-byte endpoint column
(value v6 → v7), written at `JoinMarket` connect and **never changed**: a
Release leaves the row in place with a zero bonded total, endpoint included.
LMDB `VERSION 12 → 13` for the column; a v12 datadir is refused at open.

---

## 4. `EU-D4` — RULED 2026-09-11: the witness reads the endpoint from the drawable snapshot at epoch open, joined through the record by `p_id`

Discovery is a chain read only if the witness reads **one place** — the
record, not the post that wrote it. That place is the drawable-set snapshot the challenge derivation already takes at
epoch open (`challenge_assignment.rs`, `DrawablePair { p_id, shard_id }`; §9.5
pin 1's canonical order). The pair is the sort key; the endpoint is **not** a
field on it — it joins through the bond record by `p_id`, one lookup, at the
moment the drawable set is snapshotted. A `JoinMarket` that connects
mid-epoch is record-effect at connect and mechanism-effect at the next epoch
open, exactly as `HoldingsUpdate` is.

Stated here rather than left to whoever writes the fetcher, because the
alternative — the fetcher walking the record's post history — is the design a
reader of the wire would reach for, and it is wrong.

---

## 5. Rejected, by name — 2026-09-13

Every entry below was written as RULED between 2026-08-10 and 2026-09-12 and
is REJECTED by §1. The numbers are kept so a citation resolves here.

- **The 2026-08-10 "carrier ruling"** (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7
  item 2, Mutability and Carrier paragraphs) — rotation-in-place via a
  kind-4 `EndpointUpdate`; REJECTED, the paragraphs replaced in place. It was
  recorded as a ruling; it was not Rick's.
- **`EU-D2`** — the cold key for a non-`JoinMarket` record, "reached by
  widening the selector one arm": there is no arm to widen. C0's finding and
  predicate (`requires_cold_authority`, `cold_authority_pin`) stand as landed
  in #703 for Release and the debit arms; the custody vocabulary ("cold" =
  principal tier, not cold signing) stands with the decision-log entry of
  2026-09-12.
- **`EU-D5`** (rotation rate unbounded), **`EU-D6`** (enumeration a design
  input — as a rotation-rate argument), **`EU-D7`** (refuse `EndpointUpdate`
  on a zero-bonded record), **`EU-D9`** (the two laundering KATs),
  **`EU-D11`** (the kind-4 vin shape), **`EU-D12`** (the per-kind
  `archival_bond_endpoint_update_log` journal), **`EU-D13`**
  (`PENDING_POST_VERSION` 10→11 with the producer) — REJECTED with the kind.
- **`EU-D8`** — the `hs_id` derivation to take a rotation index under a v2
  label, V1 deleted, V2 minted — REJECTED. `ARCHIVAL_P_DERIVE_V1` and the
  `shekyl-archival-p-hs-id-ed25519-v1` label stay as they are. The
  decision-log entry that authorized the retirement is WITHDRAWN by the
  2026-09-13 entry. The debt `EU-D8` noticed on the way — V1's regenerator
  is not citation-gated — is real and is a FOLLOWUPS line.
- **`EU-D10`** — the sequence C0 → A → B+C1 → D. C0 (#703) and A (#712, this
  record's first version) landed. B+C1 was built as PR #717 and **excised
  before merge**: its JoinMarket half is the PR this record now describes;
  its kind-4 half is kept at archive tag
  `archive/feat/eu-b-c1-endpoint-update-wire-2026-09-13`. D's design pass
  (a rotation window, a persisted rotation hint, a submit battery) was
  written, never built, and is kept at
  `archive/feat/eu-d-hs-id-rotation-2026-09-13`.

---

## 6. Handed onward as premises (unchanged)

- **TJ-B** (the daemon-side fetcher): `EU-D1`, `EU-D4`, and the SP-T3
  daemon→wallet re-base obligation. This record does not specify it.
- **Shard assignment** (`-29505`): its own unopened round.
- **The credit-wire cutover deletion** (`ARCHIVAL_CREDIT_WIRE.md` §2):
  separately scoped.
