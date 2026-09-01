# P2P-2 — dispatch brief for the P2P protocol design round

**Status:** DRAFT for steering review, 2026-09-01. Dispatches the P2P-2 design
round, whose deliverable is `SHEKYL_P2P_PROTOCOL.md`. This brief is not that
spec and rules nothing: it states what the round must decide, what it must
treat as already decided, and what "done" means. Ratification is Rick's, per
cluster, on the relay-round convention.

**Pinned:** `dev` @ `19328a46c9052eee6892895b96f852235a9a689a` (verified against
`git ls-remote origin` at 2026-09-01T17:18Z — the merge of PR #590, which
followed #588). Both source documents are live at this sha. Re-verify before
the round opens if `dev` has moved; the round's own reads get their own pin.

**Nothing is implemented in P2P-2.** The round produces a normative
specification and its wargame record. Code is P2P-3.

---

## 0. Two corrections to the dispatch premises, applied here

Recorded first because both are load-bearing on the round's own gates, and
because a brief that silently absorbs a wrong figure hands it to the spec.

**(a) The completion gate covers 46 bucket-4 rows, not 44.** The steering
requirement cites 44, which was the census's count before its pre-merge review
round. The merged instrument at this pin is **57 bucketed rows — 3 / 6 / 2 /
46**; PWC-A6a and PWC-E4a were split in, and PWC-E4/E8 were recounted. The
number is checkable at the pin:

```
grep -cE '^\| PWC-[A-F][0-9]+a? \|' docs/design/P2P_1_WIRE_CENSUS.md   # 57
```

Counts stay load-bearing (steering requirement 7), so §4's disposition table
is built against **46**.

**(b) PW-8's WireGuard cost figure is mismatched, and the round must not quote
it.** The register flagged the WireGuard timers as *"not re-verified at primary
source"*; that debt is now discharged — **not from the corpus, which does not
contain the paper** (see §1.3), but by fetching Donenfeld's paper directly.

At source, WireGuard's handshake is **148 B initiation + 92 B response = 240 B**
(§5.4.2 / §5.4.3 field layouts, arithmetic reproduced in §1.3). BOLT-8's
classical handshake is 166 B (50 + 50 + 66), already verified in the register's
second round. **240 : 166 is ≈ 1.45×, not the ~15× PW-8 states.** The register's
"~2.4–2.8 KB per interval" is the size of a *hybrid* re-handshake, compared
against a *classical* BOLT-8 figure — apples to oranges.

**PW-8's ruling survives intact**, because it never rested on the ratio: its
stated basis is that PCS's precondition rarely holds on an open gossip network,
and the register says so explicitly ("on the merits rather than on cost"). The
figure is decorative and wrong, which is exactly why it must be corrected
before it is quoted into a normative spec. Two further primary-source
corrections in §1.3.

---

## 1. Inputs

Three, all at the pin. Every row is cited by id; nothing is carried on
recollection.

### 1.1 The requirements register — `P2P_2_REQUIREMENTS_REGISTER.md`

All `PW-` rows, including the 2026-09-01 implementation-path round:

- **PW-7a** — `snow` read at source, ruled **read-not-depend**. It already has
  HFS; the blocker is that `KemChoice` is a closed single-variant enum, making
  adoption a fork rather than a resolver swap. Neither `snow` nor `pqcrypto-*`
  is in `rust/Cargo.lock`.
- **PW-7b** — **HFS suffices for `NN`.** PW-5 is moot for gossip; PW-4 is
  **discharged by the check its own status ordered**. Scoped gossip-only:
  PW-5 stays live for the operator-pinned patterns its text names.
- **PW-7c** — **`e1`/`ekem1` semantics are normative in
  `SHEKYL_P2P_PROTOCOL.md`'s own text**, with `noise_hfs_spec` cited as
  *provenance, not authority*. A genesis-frozen wire cannot take authority from
  a draft marked unstable. This is a **round deliverable**, not a background
  note: the spec must contain the token sequence, `ck` derivation, KEM
  placement and padding band as its own normative text (§2.1, D-T4).
- **PW-7d** — **snow as a test-only differential partner** for the classical
  half of the KAT suite: a **rule-17 wargame option parked for P2P-3**, not a
  P2P-2 decision. The round records it as an open option with its arguments;
  it does not resolve it, because the choice needs the KAT design as input.

### 1.2 The wire census — `P2P_1_WIRE_CENSUS.md`

All `PWC-` rows, their evidence classes, and §9's correction log. The census's
own §7 records what it deliberately did not cover; those exclusions are
scope fences here (§6), not gaps for the round to fill opportunistically.

### 1.3 The papers corpus — and its actual state

**Verified, not assumed.** The steering note says WireGuard and BOLT-8 are "now
in the corpus"; at this pin they are **not** in the local paper directories.
`find` over `~/Nextcloud/Documents` and `~/Downloads` returns only unrelated
WireGuard material (VPN cheatsheets, logos). Present and usable:
`2022-539_PQC_Noise.pdf`, `2608.00954v1_Noise_PQC.pdf`,
`2504.17809v1_Levin_protocol.pdf`, `2509.10214v1_Levi_p2p.pdf`,
`2607.07062v1_TOR_Deanonymizing.pdf`, `2023-423_Hybrid Signatures.pdf`, plus
the Shi et al. NDSS 2025 eclipse paper fetched during the census.

The WireGuard citation debt is nonetheless **discharged**, by fetching
`wireguard.com/papers/wireguard.pdf` and reading it directly. Verified at
source, and each correcting the register:

| Register says | Source says | Consequence |
| --- | --- | --- |
| WG re-handshake ≈ 2.4–2.8 KB, ~15× BOLT-8 | 148 B + 92 B = **240 B**, ≈ **1.45×** BOLT-8's 166 B | §0(b). Fix on the register's first touch; never quote the old ratio |
| "WireGuard is `Noise_IK`" | `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (§5.1 Construction) | Minor but real: **IKpsk2**, not plain IK. Does not disturb PW-19a's argument, which turns on the `K` pre-message, present in both |
| Option (b) carries "a cadence fingerprint requiring jitter *and* padding to suppress" | WG **already jitters**: "an additional amount of jitter is added to the expiration" (§6.1) — but *to prevent two peers initiating simultaneously*, not to defeat an observer | The accurate claim is that WG's jitter is **not sized for fingerprint suppression**, not that jitter is absent. State it that way or the round inherits a false premise about what (b) would cost |

Verified constants (§6.1), for any row that needs them: Rekey-After-Messages
2⁶⁰; Reject-After-Messages 2⁶⁴ − 2¹³ − 1; **Rekey-After-Time 120 s**;
Reject-After-Time 180 s; Rekey-Attempt-Time 90 s; Rekey-Timeout 5 s;
Keepalive-Timeout 10 s.

**Standing instruction:** any figure quoted into `SHEKYL_P2P_PROTOCOL.md` must
be traceable to a source read in this round or a prior one that named its
verification. PW-3's pattern attribution (PWC-X7) is still **unverified** — the
NoisePQC++ table is not in the repository — so no pattern-specific byte count
may be quoted until it is re-read.

---

## 2. The deliverable

`docs/design/SHEKYL_P2P_PROTOCOL.md` — a **normative specification**, organised
by the four clusters below, with a **wargame table per decision**. Each
decision carries: the options considered, the adversary and channel each option
answers (per the threat-model discipline: name `T` and its channel or there is
no threat model), what is conceded, and the falsifier that would reopen it.

A decision without a stated falsifier is not ruled; it is deferred with extra
words.

### 2.1 Cluster T — the transport, concrete

Converged inputs: pattern (`NN`-family, PW-19a), PQ mechanism (HFS hybrid,
PW-7b), implementation path (native over `shekyl-crypto-pq`, PW-7a). What
remains is to make them concrete and normative.

| id | Decision | Grounded in |
| --- | --- | --- |
| D-T1 | The exact handshake: token sequence, `ck` derivation, where the ML-KEM shared secret is mixed | PW-1, PW-2, PW-7b |
| D-T2 | **Fixed-size padding band**, independent of pattern and KEM — named as a hard requirement, not assumed as a side-effect of encryption | PW-3 (**do not quote its byte figure**, PWC-X7) |
| D-T3 | Rekey: BOLT-8-style `ck', k' = HKDF(ck, k)`, per-direction, nonce reset | PW-8 (ruled; carry the §0(b) correction) |
| D-T4 | **`e1`/`ekem1` semantics written normatively in this document**, `noise_hfs_spec` cited as provenance only | **PW-7c** |
| D-T5 | Wire prefix: what replaces `LEVIN_SIGNATURE`'s fixed 8 bytes | PWC-A1, PW-9 |
| D-T6 | Packet limits derived from largest legitimate message, replacing two inherited and disagreeing constants | PWC-A5, PWC-F3, PW-10 |
| D-T7 | Whether compression survives, and if so its position relative to encryption | PWC-A10 (recorded as **conditional**, not a present defect), PW-13 |
| D-T8 | KAT strategy — Shekyl mints its own; **PW-7d's differential-partner option is recorded, not decided** | PW-6, PW-7d |

### 2.2 Cluster B — behavioral commitments

The cadence, limit and drop behavior the census enumerated. Most of the
bucket-4 mass lives here.

| id | Decision | Grounded in |
| --- | --- | --- |
| D-B1 | Rate limiting on handshake / timed-sync / ping — currently **absent** | PWC-E2, PW-15 |
| D-B2 | Cadence jitter — currently **absent**; a distinct fix from D-B1, and neither substitutes for the other | PWC-E1, PWC-E3, PW-28 |
| D-B3 | Per-command caps: derive them, and decide the unknown-command fallthrough that currently reaches `size_t::max` | PWC-C7 |
| D-B4 | Unknown flag bits: reject at ingress, or keep accepting | PWC-A6 / **PWC-A6a** (the codec accepts them; no relay carries them today) |
| D-B5 | `return_code` on notifications — inherited RPC-over-Levin affordance | PWC-A7, PW-12 |
| D-B6 | The two block-propagation paths (2001 alongside 2008) — collapse or keep, on a chain with no fluffy transition | PWC-C3, PW-27 |
| D-B7 | Drop semantics: `drop_connections`-by-host, the score floor, and whether the **inherited** no-drop-offense set is adopted deliberately | PWC-E7, PWC-E8, PWC-E9 |
| D-B8 | Dead surface: the two lineage-dead structs and the never-driven 43-second timer | PWC-F1, PWC-F2, **PWC-E4a** |

### 2.3 Cluster I — identity and Sybil resistance

| id | Decision | Grounded in |
| --- | --- | --- |
| D-I1 | Session identity: fully ephemeral, no durable peer id on the wire | PW-19, PW-19a, PWC-D4 |
| D-I2 | Peerlist disclosure: size, anonymisation, and whether both handshake and timed-sync carry it | PWC-D1, PWC-D2, PWC-B4, PW-16 |
| D-I3 | Tenure recognition: address-keyed, never a wire field; **and the `first_seen` ordering that decides which anchors take the slots** | PW-17, PW-18, PWC-D5, §5.4 |
| D-I4 | **Specify `ρ` / `g_max`** — the work-based admission and eviction mechanism | PW-23, PW-25 |
| D-I5 | **Close Q-10 across documents**: update `DAEMON_RELAY_PRIVACY.md` itself to record the resolution | **PW-26** — a one-way read is not closure |
| D-I6 | The Shi et al. residue: graylist and whitelist sub-attacks, both **unaddressed** | §5.2, PWC-D3, PWC-D10, PWC-D11 |

### 2.4 Cluster A — the archival submission-path gap

| id | Decision | Grounded in |
| --- | --- | --- |
| D-A1 | Does the archival firewall / P-transport design cover the **serve-credit submission** path, or only serving? | PW-22, PWC-X5 |

The census narrowed this from "is there a leak" to a falsifiable claim:
production submission runs through the `Local` posture, and **no production
caller selects the per-`P` `OwnRemote` arm**. Name such a call site and D-A1 is
refuted. Required reading, carried from the register unchanged:
`ARCHIVAL_FIREWALL_GATE6.md`'s GF-7 rounds (including the finding that cover
parameter `r` is cover-blind, which **stands** — only the instrument was made
fail-closed); the cover-is-always-protocol-added ruling, which is in
`ARCHIVAL_BOND_CONSTRUCTION.md`, **not** GATE6; the SP-T persona-transport
lane; and the SH serving-host arc, whose custody boundary speaks to serving and
is silent on submission.

---

## 3. Invariants — requirements in, not subjects

Stated up front so no cluster reopens them. A round that re-litigates these has
misread its scope.

1. **Ratified D++ / relay-privacy mechanisms are requirements-in.** The stem
   graph, `STEMS = 2`, the embargo backstop, the per-zone `hop`, the arrival-is-
   stemmed rule (Q12-U2, landed in PR #459 — **not open**, whatever an earlier
   brief said). The transport composes with these; it never absorbs their job.
2. **No authentication between unknown peers.** Not reopenable. Jointly
   entailed by three landed rulings, cited together because no single sentence
   states it: `RPC_TRANSPORT_POSTURE.md` §2.1 (scope — strangers by
   construction); `DAEMON_RELAY_PRIVACY.md` §12.10 (mechanism — admission is
   work, not identity); `Q12_D6A_PEER_DISCOVERY_RUN.md` (anti-ruling — a stable
   p2p identity "would hand back the linkage the transport layer is built to
   deny", rejected twice). `XK`/`IK` are **inapplicable, not declined**: the
   `K` pre-message is the assumption that the parties are not strangers.
3. **Structural unlinkability.** Privacy is not a setting; the same guarantees
   for everyone. No mechanism may make p2p membership paid or give relay peers
   persistent identity (PW-21, rejected once already).
4. **PW-4 / PW-5 are moot for gossip** (PW-7b) and are carried as ground, not
   re-argued. PW-5 remains live for operator-pinned patterns — that is the RPC
   lane's question, not this round's.
5. **The transport's adversary is the non-participant path observer.** The
   counterparty is conceded. Content is public by design; **arrival metadata is
   not**, and is D++'s scope — taxed, not eliminated. Do not compress this to
   "recording peers see only what's public anyway": that premise is what
   weakens the stem-phase properties.

---

## 4. Completion gate

**Every one of the census's 46 bucket-4 rows carries an explicit disposition,
and the dispositions sum to 46.** No row is ratified by silence — that failure
mode is the reason both censuses exist.

Three dispositions, and only these:

| Disposition | Meaning | Evidence required |
| --- | --- | --- |
| **Ruled** | The round decided it | The wargame table entry, with its falsifier |
| **Absorbed** | A protocol decision subsumes it | The `D-` id that absorbs it |
| **Deferred** | Not settled in this round | A **named blocker** and the owner — per rule 22, a deferral without a named blocker is not a deferral |

The round's own arithmetic must close, in its closing section:

```
ruled + absorbed + deferred = 46
```

`PWC-X` rows carry no bucket and are excluded, as they are from the census
totals. Bucket-3 rows (PWC-F1, PWC-F2) are already dispositioned as deletion
candidates and route to the p2p lane — they are **not** RK-cutover residue; the
census's §9 records the provenance correction and why the routing changed.

**Also owed at close:** every `PW-` and `PWC-` row that a decision touches gets
a pointer back to the `D-` id that settled it (steering requirement 7). A
census row whose question was answered but whose text still reads open is the
same defect as ratification by silence, one document over.

---

## 5. Ratification

Rick rules **per cluster**, on the relay-round convention. The round presents a
cluster's wargame tables, takes a ruling, and moves on; it does not batch four
clusters into one decision, and it does not implement.

The umbrella chat reviews the round's output before it goes to ratification.

---

## 6. Scope fences

- **RPC is out.** `RPC_TRANSPORT_POSTURE.md` owns it; §2.1 is the boundary
  (`:101-107` at this pin — the register's `:99-106` is one line short). RT-4's
  pinned-mutual-TLS is **not transferable**: P2P's peer is a stranger by
  construction, so a borrowed mechanism needs its own justification.
- **Relay-privacy ratified mechanisms are invariants, not subjects** (§3.1).
  **Explicitly allowed as extension:** stem extension across transports, per the
  ProxyMark ruling — the layers must compose, and each must own its actual
  scope.
- **Consensus rules are out.** Block and tx acceptance is
  `CONSENSUS_RULE_CENSUS.md`'s denominator. The one deliberate crossing is
  PWC-E7/E8, where a *pool* verdict determines a *connection* outcome.
- **`levin_notify.cpp` / carrier cadence is out** —
  `COVER_TRAFFIC_RESTORATION.md` and `shekyl-relay-privacy` own it. The
  wire-visible consequences (2002's `_` padding and `dandelionpp_fluff`,
  fragmentation sizing) are in scope; the cadence is not.
- **No implementation.** P2P-3.

---

## 7. Rider — the register's first touch

Two corrections ride the register's next edit, neither of them this round's
subject but both owed:

1. **§12.11 / `ρ` citation decay.** `DAEMON_RELAY_PRIVACY.md` §12.11's body is
   **superseded in part** by two banners (the Exploit tier is deleted; the live
   mechanism is a uniform random draw over the non-cooled admissible set,
   §§52/53/54). And `ρ` is **not mentioned in §12.10 at all** — its canonical
   statement is §13.5. PW-25's claim survives; its pointer does not. D-I4 and
   D-I5 must read the live text, not the superseded body.
2. **PW-8's WireGuard figures** — §0(b) and §1.3. The ruling stands; the
   ratio, the pattern name and the jitter claim do not.

---

## 8. What this brief does not do

It does not rule any bucket-4 row, choose a handshake, specify `ρ`, or resolve
PW-22. Those are the round's, and a brief that pre-empted them would be the
round happening in the wrong document with no wargame record.

It also does not re-open the invariants in §3. If the round finds one of them
untenable, that is a finding to raise with steering explicitly — not a decision
to take inside a cluster.
