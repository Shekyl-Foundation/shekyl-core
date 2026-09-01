# P2P-2 requirements register

**Status:** OPEN — steering-reviewed 2026-08-31; sound, spot-checked (four
`drop_connections` sites and §12.10's framing independently confirmed),
ready to land as a tracked doc. Four deltas from that review are folded in
below (PW-3 correction, PW-22 rewrite, PW-27, PW-28). Sequencing ruling:
this lands first with `PW-` registered in the index at
birth (rule 94 §1); P2P-1 (the wire census) is the next artifact and absorbs
§7's open tasks as census work rather than a separate errand. This is not
the P2P-2 dispatch brief; it is the durable input the brief gets drafted
from, so the rows below survive independent of any one chat transcript.

**Pinned:** `dev` @ `ab3cc98e6eb73db2b309730ccc9853ba4ea95e7d` (fetched fresh,
verified against `git ls-remote origin` at time of writing — 2026-08-31).
Every source claim below was read at this sha; re-verify before drafting the
brief if `dev` has moved.

**Identifier family:** `PW-` (P2P wire), checked unique against the index's
existing families (CW/VG/SH/CT-ACT/PC/RF/SO/CR/CB/F-D/…; `P-` is distinct
under the alphabetic-prefix-until-digit test) — no collision. Registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in the landing PR
(rule 94 §1).

**Scope boundary, ratified by prior work, verified this session:**
`RPC_TRANSPORT_POSTURE.md` §2.1 (`:99-106`) — "P2P is not RPC... RPC is
operator-to-operator; P2P is adversarial by design and hardened separately."
RT-4's pinned-mutual-TLS mechanism (`:223-227`, "No CA... every client is a
device the operator physically holds — there is no delegation, only
enrolment") is therefore **not transferable** to P2P by default; P2P's peer
is a stranger by construction, so any borrowed mechanism needs its own
justification, not RT-4's.

---

## 1. Transport — hybrid-PQ Noise, working assumption

| ID | Finding | Evidence | Status |
| --- | --- | --- | --- |
| PW-1 | Hybrid Noise (classical DH + ML-KEM, HFS patterns) has a generic computational security proof (fACCE model) for confidentiality/authenticity, matching or exceeding classical Noise's per-pattern proofs. | `2022539_PQC_Noise.pdf` (Angel/Dowling/Hülsing/Schwabe/Weber, CCS 2022) | Grounded — not a novel/unanalyzed composition |
| PW-2 | Official HFS composition method exists, authored by the Noise framework's own designer, with a working reference implementation covering NN/XX/IK/KK in classical, pure-PQ, and hybrid modes. | `noise_hfs_spec` (Perrin); `2608.00954v1_Noise_PQC.pdf` (NoisePQC++, QCE 2026) | Grounded |
| PW-3 | **Handshake size is a strong new fingerprint — ~14× classical→hybrid overhead.** A censor can bucket by first-flight byte count alone, no decryption needed. **Pattern attribution needs re-pinning before this cites a spec figure**: the 192 B classical figure was extracted adjacent to the NN pattern's row, not confirmed against XX — the ~14× magnitude holds either way, but re-read the table before quoting a specific pattern's bytes in the brief. | `2608.00954v1_Noise_PQC.pdf` Fig. 6/measured totals — **re-verify table alignment before drafting** | **Open — needs fixed-size padding independent of pattern/KEM in use, named as a hard requirement, not an assumed side-effect of encryption** |
| PW-4 | Ephemeral-key dual-use breaks under KEMs: classical Noise lets a peer confirm two DH results share an ephemeral share; no such guarantee exists for KEM ciphertexts. | `2022539_PQC_Noise.pdf` §2.3 | Carry as a design caveat — check nothing in Shekyl's transport design leans on this property |
| PW-5 | Static-static exchange has no direct KEM equivalent; the replacement (`skem` + key-confirmation message) costs a round trip. Directly relevant: RT-9-adjacent, operator-pinned patterns (KK/IK-family) rely on `ss`/`se`/`es`. | `2022539_PQC_Noise.pdf` §2.3 (translation recipe) | Scope the extra round-trip cost explicitly wherever a mutually-pinned pattern is used |
| PW-6 | No standardized test-vector suite exists yet for PQNoise/hybrid patterns — NoisePQC++'s own authors generated their own deterministic vectors. | `2608.00954v1_Noise_PQC.pdf` §5.2.3 | **P2P-2 must budget minting Shekyl's own pinned hybrid-handshake KATs from scratch — no external oracle to lean on** |
| PW-7 | Rust prior art exists (Clatter) but is narrower in scope (X25519-only classical side); worth reading for pattern-encoding decisions, not depending on (no-FFI discipline). | `2022539_PQC_Noise.pdf` §2.4.1 references | Informational |
| PW-8 | Rekey/forward-secrecy schedule for long-lived peer-to-peer sessions (harvest-now-decrypt-later applies to session traffic, not just the handshake; the §Scope boundary puts operator-to-operator sessions on the RPC side — this row governs the adversarial P2P wire). **Framing corrected against the primary spec (steering, 2026-09-01):** BOLT-8 is not an alternative to a Noise pattern — it **is** Noise (`Noise_XK_secp256k1_ChaChaPoly_SHA256`) plus a rekey scheme layered on top, so the axis is the **rekey mechanism**, orthogonal to the pattern choice (XK/IK/NN): **(a) symmetric KDF-chain rotation** (BOLT-8: `ck′, k′ = HKDF(ck, k)`, nonce reset to 0, per-direction chains — after 1,000 **nonce increments = every 500 messages**, each message consuming two nonces, encrypted length prefix + body; zero wire bytes, invisible to a network adversary; forward secrecy via one-way HKDF; the PQ property is inherited — every rotated key descends from the hybrid handshake's ML-KEM-mixed root). **Structural limit: no post-compromise healing, and none can be added** — PCS requires entropy the attacker lacks, and a symmetric chain has none by construction, so (a) hardened for healing *becomes* (b) or (c); the options are not independently tunable. **(b) periodic full re-handshake** (WireGuard-style, ~120 s or message-count bound): fresh hybrid entropy = post-compromise recovery + refreshed PQ contribution; the cost is a handshake-shaped on-schedule event — Shekyl's hybrid ~2.4–2.8 KB vs BOLT-8's fixed 166 B (50/50/66), ≈ 15× — a PW-28-class cadence fingerprint. Mitigation is asymmetric-cheap: jitter is local policy (no wire/key-schedule/interop change) and the fixed-size padding band is already PW-3-required for the initial handshake, so (b) reuses mechanisms that must exist anyway (BOLT-8's own encrypted length prefix + fixed act sizes are the precedent shape). **(c) PQ-KEM ratchet** — research-grade (PW-4 bites); wargame control, rejected under the get-it-right posture. **Decision restated as two steps:** (1) is post-compromise security *required*, per surface? — hypothesis: PCS matters for long-lived authenticated/operator-class links but plausibly not for ephemeral-identity NN gossip peers (PW-19: connections churn, no persistent static key, and an attacker who owns the node owns more than the session keys) — the answer may split by connection role exactly as PW-17's tenure question split by direction; (2) no-PCS surfaces take (a) (free, invisible, PQ-inheriting); PCS-required surfaces take (b) with jitter + the shared PW-3 padding band. **Pattern-axis honesty note:** production rekey precedent concentrates on the authenticated static-key surface (WireGuard = IK, BOLT-8 = XK); NN-family gossip has thinner deployment history — stated for the wargame, not implied away (recommendation unchanged: anonymity justifies NN and it is the simplest pattern; and on NN sessions (b)'s re-handshake is nearly free of identity complications — no static key to re-authenticate). | Steering rounds 2026-09-01; **BOLT-8 half verified at the primary spec** (`lightning/bolts/08-transport.md`, master: `Noise_XK_secp256k1_ChaChaPoly_SHA256`; 1,000 nonce increments = 500 messages; acts 50/50/66 B; encrypted length prefix); WireGuard whitepaper (timer/message-count re-handshake) — **fetch both into the papers corpus; WireGuard bounds still to re-verify at source before the P2P-2 brief quotes figures** (PW-3's re-pin discipline) | Open — two-step decision: (1) rule whether PCS is required, per surface (split hypothesis recorded); (2) no-PCS → (a) KDF rotation; PCS → (b) re-handshake with jitter + the PW-3 fixed-size padding band; (c) stays the wargame control |

---

## 2. Levin-inherited wire findings (Survey A's L-items + this session's addition)

| ID | Finding | Evidence | Status |
| --- | --- | --- | --- |
| PW-9 (L-1) | `LEVIN_SIGNATURE` is a fixed 8-byte constant — perfect DPI signature. | `rust/shekyl-levin/src/header.rs:14`, verified this session | Open |
| PW-10 (L-2) | `DEFAULT_MAX_PACKET_SIZE = 100 MB`, inherited not derived. | `header.rs:27` | Open — derive from largest legitimate message |
| PW-11 (L-3) | Unknown flag bits preserved verbatim in the `Flags` type (decode/encode round-trip is byte-identical) — **a latent affordance, not an active cross-relay channel on the current path**: `classify` consumes the header into command/return-code/payload (`reader.rs:458–474`) and every outbound constructor mints a fresh header with only known flags (`message.rs:25–48`), so an application relay never forwards an inbound flag word (verified: no verbatim re-forward path in the crate). Rejecting unknown bits pre-genesis stands, justified as canonical framing plus closing the latent affordance before any future path forwards raw buckets — not as closing a live covert channel. | `header.rs:29-30`; `reader.rs:458–474`; `message.rs:25–48` | Open — reject unknown bits pre-genesis (canonical framing) |
| PW-12 (L-4) | `return_code: i32` on every bucket — inherited RPC-over-Levin affordance leaking implementation state. | `header.rs:103` | Open |
| PW-13 (L-5) | Compression before encryption is a CRIME/BREACH-class oracle; interacts directly with Dandelion++'s padding/size defenses. | `compress.rs:25,32` | Open — check compression is disabled wherever padding is load-bearing |
| PW-14 (L-6) | Cross-IP identity linkage, narrowed at the tree (the L-6 carry-over was stale at this register's own pin): `rpc_port` and `rpc_credits_per_hash` are already forced to 0 on send with the RT-posture rationale in-code (`net_node.inl:2157–2163`) — the residue is the two wire *fields'* existence (redesign deletion candidates), not a live advertisement; anonymity zones announce the fixed sentinel `peer_id` (`net_node.h:115–130`, deliberately non-random, init-enforced, to prevent onion↔clearnet correlation); the live linkage surface is the **public zone's** random `peer_id` (plus `my_port` when pingback-capable) announced on handshake and ping. | `p2p_protocol_defs.h:180-196`; `net_node.inl:2150–2166`; `net_node.h:113–132` | Open — see §3 below, largely superseded by the identity-model direction |
| PW-15 (L-7, new this session) | No rate limit on Ping/Timed-Sync/handshake messages; enables both cheap connection churn and a watermarking side channel (message-rate modulation). | `2509.10214v1_Levi_p2p.pdf` (handshake flooding, throttled Timed Sync measurements); `2607.07062v1_TOR_Deanonymizing.pdf` (ProxyMark's rate-based watermark method) | Open |
| PW-16 | Peer-list disclosure, code-accurate at the pin: the handshake response dumps the full peerlist head (≤250, `P2P_DEFAULT_PEERS_IN_HANDSHAKE`) and populates `context.sent_addresses`; each 60-s Timed Sync samples up to 250 more and filters through that set (`net_node.inl:2662–2686`, `:2787–2789`). The filter is per-connection **dedup, not a bound** — a held-open connection cumulatively enumerates the node's peerlist across syncs, distinct entries each round. Topology-mapping aid for planning eclipse/Sybil attempts. | `2509.10214v1_Levi_p2p.pdf` §2.1 (mechanism re-grounded against the tree — the paper's "full list on every Timed Sync" describes Monero, not this tree) | Open |
| PW-27 (formerly Survey A U-6) | `NOTIFY_NEW_BLOCK` still lives alongside `NOTIFY_NEW_FLUFFY_BLOCK` — two block-propagation paths that must agree on validation, on a chain with no fluffy-block transition to justify the legacy one, and a path the Dandelion++ zone analysis may not have covered. Re-confirmed on `dev` @ `ab3cc98e6`: both structs present. | `cryptonote_protocol_defs.h:184` (`NOTIFY_NEW_BLOCK`), `:334` (`NOTIFY_NEW_FLUFFY_BLOCK`) | Open |
| PW-28 (cadence jitter, split from PW-15) | The **fixed 60-second Timed-Sync cadence itself** is a distinct fix from rate limiting (PW-15) — different fixes for different halves of the same finding. Rate limiting closes the flood; it leaves the fingerprint (Levi paper's anomaly detector works because the cadence is exactly standard). Cadence jitter closes the fingerprint; it leaves the flood open on its own. **Both are required, named separately so neither substitutes for the other.** | `2509.10214v1_Levi_p2p.pdf` §5 (Timed Sync frequency analysis); `2607.07062v1_TOR_Deanonymizing.pdf` (watermark-based method exploits absence of rate limiting) | Open — two rows' worth of work, do not fold into one fix |

---

## 3. Peer identity model

**Working hypothesis (direction-split by connection role — stated, not yet
verified against §12.10's actual mechanism):**

- **Outbound tenure** (guard-pinning, the peer *you* dialed) keys naturally
  on the dialed endpoint — an IP on clearnet, an onion address on Tor — and
  survives reconnects on both transports. The "address doesn't meaningfully
  exist" problem that ruled out address-based *admission* (§6.10,
  `DAEMON_RELAY_PRIVACY.md`) was about judging *inbound* diversity; it does
  not obviously block recognizing an endpoint you chose to dial.
- **Inbound tenure** is the hard case, and eclipse defense is fundamentally
  about who fills your *outbound* slots — so inbound tenure may not need to
  exist as a mechanism at all.
- **PW-17 — verify, don't adopt.** This split must be checked against
  §12.10's actual mechanism before it's treated as settled.

**PW-18 — recognition key ≠ wire field, stated as a standing rule.**
Tenure bookkeeping is local state about a relationship between this node and
one peer; it is never serialized, announced, or echoed on the wire. This
keeps "tenure needs a key across reconnects" from quietly regressing into
"put a linkable identifier back on the wire." Supporting evidence from
source: `anchor_peerlist_entry_base` (`p2p_protocol_defs.h:100`) already
keys on `(adr, id, first_seen)`, but `is_peer_used`'s outbound-connection
match (`net_node.inl:1225`) uses address alone (`!cntxt.m_is_income &&
peer.adr == cntxt.m_remote_address`) — `peer_id` is a secondary check, not
the primary mechanism. Existing code already treats address as
connection-continuity bookkeeping, distinct from trust-by-identity.

**PW-19 — fully-ephemeral session identity ("NN"-family Noise) is a real,
named point in the design space** (the person steering this round's own
proposal), not a deviation from the framework. It kills the
**transport-layer half** of PW-14/L-6 (no static handshake key to link).
It does **not** by itself touch the application-layer half:
`basic_node_data.peer_id` / `my_port` are Levin message-layer fields that
ride above any Noise pattern — deleting them (or making them per-session,
respecting PW-14's anonymity-zone sentinel constraint) is an **explicit
requirement of this row**, decided by the Shekyl-native message layer,
not a side effect of choosing NN.
Costs: identity-based banning dies (a banned peer reconnects with a fresh
key) — **see PW-20**, the required replacement.

**PW-20 — Sybil-resistance replacement is a required co-deliverable, not
optional follow-on scope.** `peer_id` and the outbound-connectivity floor
were confirmed (via `Q12_D6A_PEER_DISCOVERY_RUN.md`'s decision log) to have
**never** been a Sybil defense — "not a sybil defense, and never scoped as
one." Going ephemeral removes nothing that was load-bearing for Sybil
resistance; §12.10 (below) is the actual intended replacement and is
unbuilt. P2P-2 does not ship without it.

**PW-21 — persona-identity as a P2P admission signal was proposed and
explicitly rejected in prior work**, for exactly the right reason: "the
persona serving credential... would make p2p membership paid, give relay
peers persistent identity and correlate relay position with archival
service — a privacy regression wearing a sybil-resistance argument." (Index
row for Q12-D6a.) Do not re-propose this.

**PW-22 — archival traffic-class question, sharpened and narrowed.** The
persona's identifier is not hypothetically exposed — it's in the clear by
design: the serve-credit submission path reads `sc_p_id` straight off the
vin (`blockchain.cpp:5314` onward, confirmed this session) to look up the
bond record, and the equivalent pattern holds for bond-post and emission
(`P_canonical_id`, `blockchain.cpp:3905/4819/5097`). So origination-IP↔P
linkage is not a hypothetical ProxyMark analogue — **it is precisely the
edge the archival firewall was already designed to protect**, and the
question is not "is there a leak" but **"does the existing firewall/P-transport
design cover the serve-credit submission path, or only the serving path?"**
— a gap check against a designed system, not a fresh design question.
Required reading before this gets ruled on, none of it done yet:
`ARCHIVAL_FIREWALL_GATE6.md` (the GF-7 rounds, including the finding that
the cover parameter `r` is cover-blind), the standing ruling that cover
traffic is always protocol-added and never operator-optional, the
persona-serving transport lane (`ARCHIVAL_FIREWALL_GATE6.md` exists on
`dev`; the transport doc's exact filename wasn't located this session —
search for the "SP-T serving-loop arc" the index references), and the SH
serving-host arc (`SH-1…SH-2`, IMPLEMENTATION_INDEX — moved serving to the
far side of a custody boundary, may or may not also cover submission).
**Deferred to P2P-1 as census work, not resolved here.**

---

## 4. Sybil / eclipse resistance — §12.10's mechanism

**PW-23 — the actual anti-Sybil/eclipse design direction is work-based, not
identity-based, and is already substantially reasoned through.**
`docs/design/DAEMON_RELAY_PRIVACY.md` §12.10 ("`g_max` reframed — select
toward demonstrated work, not distinguish adversary from honest"):
admission is *select-toward-demonstrated-work* — "admit on demonstrated
propagation, evict on demonstrated dropping... transport-blind (work, not
identity)." Address/subnet/ASN are explicitly ruled out as an admission
basis (§6.10: broken on both transports — doesn't exist on Tor, lies on
clearnet). This independently arrives at the same conclusion as everything
else in this register: identity is the wrong admission signal on either
transport.

**PW-24 — the three-regime eclipse bound.** Observation (any share): out of
scope, conceded, taxed by the signal. Partial disruption: bounded to delay
by the backstop; bound = eviction responsiveness × re-entry cost,
pool-share-independent. Full eclipse: bounded by **conscription cost** —
how expensive it is to force enough of the target's outbound slots to
relay flawlessly, past the anchors. (§12.10, table + surrounding text.)

**PW-25 — status: designed, not built.** `ρ`/`g_max` is explicitly
"underspecified, blocked on Q-10" per the doc's own status header — "a
p2p-subsystem grounding... not a relay-timing one... the seal is in the
open where the p2p round owns it." This is not a gap P2P-2 must invent; it
is a spec P2P-2 must implement and close.

**PW-26 — Q-10 closure is a cross-document obligation.** When P2P-2
specifies `ρ`/`g_max`, the closure is not complete until
`DAEMON_RELAY_PRIVACY.md` itself is updated to record the resolution — the
document that declared the dependency records its discharge. Do not let
this be a one-way read.

---

## 5. Coordination points (named, not implicit)

| Point | Lanes | Note |
| --- | --- | --- |
| `shekyl-wire` / block-and-tx relay framing | C3 (consensus Rust spine) × P2P-3 (P2P implementation) | Named in the prior consensus-lane brief |
| Mempool/relay-policy rows (pool relay-decision independence from Dandelion++ authority — the RC census's own U-4-shaped question) | C2 (consensus design-round queue, mempool-policy batch) × P2P-2 | **Newly named this session — was implicit before** |
| Q-10/`g_max` closure | P2P-2 → `DAEMON_RELAY_PRIVACY.md` | See PW-26 |

---

## 6. What none of the above fixes (carry forward, don't let it substitute)

- IP-level correlation — composes with, does not replace, the existing Tor
  integration work (`shekyl-tor`, `shekyl-p-transport`).
- Traffic-class fingerprinting independent of identity/transport (PW-22).
- The Shi et al. (NDSS 2025) eclipse mechanism (trash peer-discovery
  records + priority-list poisoning + forced disconnect via anti-DoS
  double-spend response) — Shekyl's exposure to the specific connection-reset
  half is **unverified**; `drop_connections(span_origin)` exists at four
  call sites in `cryptonote_protocol_handler.inl` (`:1538,1565,1599,1619`)
  and is the right shape of mechanism to check, not yet read against the
  attack.
- Watermarking via message-rate modulation (PW-15) — a rate-limiting fix,
  independent of the identity-model outcome.

---

## 7. Open verification tasks — run as P2P-1 census work, not a separate errand

Per steering sequencing ruling: this register lands first as a tracked doc;
P2P-1 (the wire census, with its own archaeology leg) is the next artifact
and absorbs the tasks below rather than deferring them further.

1. Read §12.10/§12.11 in full against PW-17's outbound/inbound tenure
   split — confirm or falsify before it's stated as the working design.
2. Check `drop_connections` call sites (`cryptonote_protocol_handler.inl:1538,
   1565, 1599, 1619` — confirmed present, not yet read against the Shi et
   al. mechanism) for exposure to the trash-record/priority-list/forced-disconnect
   attack chain.
3. **PW-22's reading list** (`ARCHIVAL_FIREWALL_GATE6.md` GF-7 rounds, the
   cover-traffic-is-protocol-added ruling, the SP-T persona-transport lane,
   the SH serving-host arc) — resolve whether the firewall covers
   submission or only serving.
4. Confirm whether guard-pinning as currently seeded (`ANCHOR_CONNECTIONS_COUNT
   = 2`) needs to survive a full reconnect or only an unbroken connection —
   decides whether PW-17's outbound-tenure hypothesis needs any
   cross-reconnect recognition key at all.
5. Re-verify PW-3's pattern-attribution against the NoisePQC++ table before
   any spec figure is quoted in the P2P-2 brief.