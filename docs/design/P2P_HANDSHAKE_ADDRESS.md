# P2P handshake: `peer_id` → announced address (execution note)

**Status.** DRAFT — build-and-hold unit for alpha.8, dispatched by steering
2026-09-06 on Rick's authorization. Base: `fix/peerlist-trust-is-earned`
(#637 head `65d437807`, boundary agreed with its lane; contains dev
`66bcf1f0f`). Branch: `p2p/basic-node-data-address`. **This unit executes an
already-ratified amendment** — the `peer_id` jobs table and adopted option in
`SHEKYL_P2P_PROTOCOL.md` ("No identifier on the wire; nonce + same-host cap +
local session-state flag, and the back-ping deleted outright") — it does not
re-decide it. Where this note and that doc disagree, the doc wins; one open
sequencing question (Q3) and one type-discipline question (Q1) are held for
steering.

**The ruling (as relayed).** `basic_node_data`'s self-declared `peer_id` is
deleted; an `address` field typed `epee::net_utils::network_address` absorbs
`my_port`. Four fields become three: `network_id`, `address`,
`support_flags`. A peer asserting its own identifier asserts nothing; a
handshake honestly says **there is a peer at this address** — a hypothesis
about WHERE, never a claim about WHO. No new codec: `network_address` is
already on the wire in `peerlist_entry.adr`.

**The governing check**, applied to every successor: does the mechanism let
anything conclude that two observations involve the same party? If yes —
forbidden, stop. No durable identifier under a new name; nothing keyed on
the address that survives a reconnect. (One legal asymmetry, from the
amendment: self-knowledge is not a claim about a peer.)

---

## 1. Jobs and their ruled successors (per the amendment's table)

| # | Job | Ruled successor | This unit |
|---|-----|-----------------|-----------|
| 1 | Self-connection detection at handshake | **Zone-scoped handshake nonce** (emit random N; an arriving handshake carrying an N you recently emitted is you; comparison ONLY within the arriving zone — the inherited cross-zone-oracle warning at `handle_handshake` is preserved by construction). Owner: **PWD-T1**; the nonce is **load-bearing for D++ stem width** and its failure mode is silent, so T1 carries a stem-width falsifier | Sequencing gap — see **Q3** |
| 2 | Pre-dial "stored id is me" filter (`is_peer_used`) | Same job as #1, earlier; pure optimisation, loss = one wasted dial that #1 catches. Precision from the P2P-2 cluster-E round (PWD-E5 lane): the address-based pre-dial check at `zone.m_our_address == candidate.adr` is **dead on the public zone today** — `m_our_address` is assigned only in the `--anonymous-inbound` block — so public pre-dial self-avoidance is effectively absent before this unit and stays absent after it; the nonce is the public zone's correctness backstop. If PWD-E1/E2/E3 later give the node a known public endpoint, the optimisation can return on that round's terms | Dies with `peerlist_entry.id`; nothing built |
| 3 | Duplicate-connection avoidance (id arm of `is_peer_used`) | **Address-based same-host outbound cap** — the amendment rules it "not optional cleanup; the condition under which removing the field is safe": white evicts per host but gray holds many ports per IP. **Concession, per PWD-E4 (RULED 2026-09-06): host is cheap to multiply on both transports (a /24 gives 256 free hosts on `public_` as surely as a keypair gives one onion), so the cap bounds honest duplicates and the single-IP-many-ports shape specifically — nothing adversarial beyond that, in any zone.** It restores the structural parity white already had (one entry per host), not a sybil bound — the id arm it replaces was no sybil bound either | **The minimal cap (one outbound connection per host) ships in this unit** — the same successor-ships-with-removal logic steering ruled for the nonce. Outbound diversity beyond it is PWD-B9's row |
| 4 | Back-ping (`try_ping` + `COMMAND_PING` echo) | **Deleted, not replaced — the command with it** (`SHEKYL_P2P_PROTOCOL.md:563`: "the back-ping is deleted. COMMAND_PING (1003) is deleted with it"; PWD-B10 carries the deletion, PWC-B1 takes the command off the wire surface; four p2p commands become three). Its only job was gating whitelist promotion of an inbound peer, which PWD-I2 forbids. The echo is also independently forbidden by the governing check — it concludes handshake-peer == ping-target | **Executed here**: `try_ping`, `handle_ping`, `COMMAND_PING` (both stacks), `PING_OK`, and the Rust `PingRequest`/`PingResponse` + dual-stack PING step all go. A status-only ping was considered and withdrawn: no job survives B10's inventory, and re-introducing a deleted command is not a narrowing |
| 5 | Handshake-complete sentinel (`context.peer_id != 0`) | **Explicit local session-state flag, never on the wire** (ruled in the amendment; `connection_context` already carries typed state — the flag reads `handshake_complete()`) | Executed here; `for_each_connection`/`for_connection` drop the `peerid_type` parameter |
| 6 | Outbound retry set keyed on `peer.id` | **Address-keyed retry set** (the address is what a dial targets; the id was standing in for it) | Executed here |
| 7 | `peerlist_entry.id` (persisted) | Durable identifier keyed to an address — the forbidden shape. Deleted. Persisted-shape change **folds into #637's 7→8 bump** (v8 unreleased; one bump for both changes is the amendment's own recorded expectation; `load_peers` drops pre-current stores wholesale, so no old-shape reader is needed) | Executed here, on #637's base |
| 8 | Anon-zone sentinel machinery (`ANON_ZONE_SENTINEL_PEER_ID`, doctrine block, `init` assertion) | Deleted with the field; the eclipse-completion-oracle doctrine becomes the rationale for the field's absence (the handshake announces WHERE, never WHO) and moves to the new field's documentation | Executed here |
| 9 | Introspection (`get_announced_peer_id`, rpc_facts `peer_id`, log formatting, timed-sync pair type) | Removed or re-typed to address/state; rpc_facts drops a field that no longer exists | Executed here |

## 2. The `address` field's per-zone semantics (no pingback exists)

With the back-ping deleted and PWD-I2/#637's earned-trust model in force,
an advert is never "verified then promoted" — it enters **gray**, and white
is earned in-process by an actual outbound connection.

- **Public zone:** a port-only self-advert — `ipv4{0.0.0.0, port}` (ipv6
  analogue). The advertised host half is **never read**: the acceptor takes
  the advertised `.port()` and the **socket's** remote host as separate
  inputs and constructs the gray-list entry from those — never by patching a
  received `network_address`. The socket supplies the host binding
  (a dial proves reachability; an announcement proves nothing). Pinned by a
  test: a handshake advertising `ipv4{9.9.9.9, port}` from socket host
  `1.2.3.4` records `1.2.3.4:port` in gray and never `9.9.9.9`.
- **Anonymity zones, serving:** `zone.m_our_address` (self-declared, dialable
  — the only verification an overlay address admits). Enters gray likewise.
- **Anonymity zones, dialer-only / `--hide-my-port`:** the zone's
  unknown-address sentinel. Stated so reviewers need not re-derive: (a) an
  unknown-host advert is never written to any peerlist (undialable-entry
  discipline, `sanitize_peerlist` posture); (b) the type tag reveals the
  zone, which the acceptor already knows from its own listener — no new
  information.

## 3. Mechanical coupling for the store constant (gap taken here)

`CURRENT_PEERLIST_STORAGE_ARCHIVE_VER` has **zero mechanical coupling**
anywhere in the tree (verified by the #637 lane: all four references are
inside `net_peerlist.cpp`; rule 42's CI gate covers LMDB, not this store).
This unit adds the bite: a fixture test serializes a fixed `peerlist_types`
and compares against a digest that is a **checked-in hex literal typed into
the test** — never computed from the build under test, or the oracle
iterates its subject and passes for every shape. The serialization goes
through the **portable** archive path explicitly (`new_format`): the plain
`binary_iarchive` embeds a boost library version in its header, so a digest
over it moves on a toolchain bump with no shape change, and the first
spurious red would get the gate weakened. The same test asserts the
constant's value, and its failure message names BOTH observed values — the
digest that changed and the constant that did not — because a bare digest
mismatch reads as "someone edited the fixture" and invites the wrong fix.
Observed red (shape mutated, constant held, literal digest in place) before
trusting it. (Gate constraints per the #637 lane's review; the ping-job
inventory in §1 row 4 was independently reproduced here before PWD-B10's
text was read — same sole-invoker result.)

## 3b. What this shape leaves open for PWD-E2's verifier (PWD-E6)

`--p2p-external-port` stays and becomes an operator-supplied **candidate**
(PWD-E6, ruled). This unit does not build the verifier and does not foreclose
one; stated plainly, as the round asks:

- **The announced value is still DECLARED, not verified** — exactly its status
  on `dev` today, since the back-ping that once "verified" it verified only a
  port the peer had already asserted. This unit changes the value's *shape*
  (an address absorbing the port), not its epistemic status, so it neither
  adds nor removes a verification claim.
- **There is exactly one construction site** — `get_local_node_data` — where
  the announced address is derived from `m_external_port ? m_external_port :
  m_listening_port` under the announce gate. A verifier gates that one site
  ("announce only a candidate that passed"), so E1's ruled shape (sources
  propose, a verifier decides) drops in without touching the wire type.
- **E2(a) hairpin self-dial is admitted, and this unit supplies its
  recognizer**: (a) is "dial the candidate, recognise our own nonce on
  accept", which is precisely `mint_recorded_handshake_nonce` +
  `detect_self_handshake` — already zone-scoped and single-fire here. A
  hairpin verifier needs no new mechanism from this lane.
- **E2(b) peer-assisted dial-back is admitted too**, and nothing here reads a
  peer-reported port as truth: the acceptor takes an advertised port only as
  a **gray candidate** and never as a verified endpoint, which is the same
  minted-versus-observed line (b) draws. (b) would read its port from our own
  accepting socket, a path this unit does not touch.
- Not admitted, and not by accident: (c) accepting a peer's echo directly —
  the round rejects it on its face, and this unit's receive side already
  refuses to read an advertised host at all.

## 4. Open questions for steering (recommendations attached)

- **Q1 — address type discipline.** Keep `network_address` as the field type
  (ruling's no-new-codec reason) and make never-read-the-advertised-host
  STRUCTURAL on the receive side (separate port + socket-host inputs), with
  the §2 test. **Recommend: yes.**
- **Q3 — the self-detection gap between this unit and PWD-T1.** This unit
  deletes both current self-connection checks; the ruled successor (the
  zone-scoped nonce) is owned by PWD-T1, which is not yet drafted. Between
  the two, a self-edge is undetected — and the amendment itself binds that
  failure to silent D++ stem-width halving. Options: **(i)** this unit
  carries the interim nonce as a `COMMAND_HANDSHAKE` **request-level** field
  (NOT inside `basic_node_data` — the three-field ruling holds; the
  amendment itself calls the nonce "a handshake token", which is exactly
  what a request field is), zone-scoped windows per the amendment's
  requirement, migrating into T1's token when T1 lands; **(ii)** accept the
  gap until T1, arm the stem-width falsifier now. **Recommend (i)**:
  deferring the only detector to an undrafted spec widens a silent-failure
  window, and the token's semantics are already ruled — this is carriage,
  not design.

## 5. Cross-stack and gates (the #587 method)

Both stacks in one PR: Rust `BasicNodeData` gains `address`
(`NetworkAddress`), loses `peer_id`/`my_port`; `PingRequest`/`PingResponse`/
`PING_OK`/`COMMAND_PING` deleted; dual-stack harness reworked (handshake +
timed-sync + support-flags remain the live proof); payload KATs updated with
red observed before test edits. C++ build + p2p suites; fmt/clippy/test
workspace gates CI-exact; build-and-hold — push and PR only on Rick's word.
