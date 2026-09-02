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

```bash
grep -cE '^\| PWC-[A-F][0-9]+a? \|' docs/design/P2P_1_WIRE_CENSUS.md   # 57
```

Counts stay load-bearing (steering requirement 7), so §4's disposition table
is built against **46**.

**(b) PW-8's WireGuard cost figure is mismatched, and the round must not quote
it.** The register flagged the WireGuard timers as *"not re-verified at primary
source"*; that debt is now discharged, by reading Donenfeld's paper at source
(the corpus also carries it — see §1.3).

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

Three inputs, and **each carries its own pin** — the register and census at
`shekyl-core` `dev` `19328a46c`, the papers corpus at `shekyl-dev`
`4cabe8ef2` (§1.3), because they live in different repositories and drift
independently. Every row is cited by id; nothing is carried on recollection.

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
  note: the spec must contain the token sequence, `ck` derivation and KEM
  placement as its own normative text (§2.1, PWD-T4). *Not* a padding band — see
  §1.4, which re-derives PW-3 and finds the band does not defend.
- **PW-7d** — **snow as a test-only differential partner** for the classical
  half of the KAT suite: a **rule-17 wargame option parked for P2P-3**, not a
  P2P-2 decision. The round records it as an open option with its arguments;
  it does not resolve it, because the choice needs the KAT design as input.

### 1.2 The wire census — `P2P_1_WIRE_CENSUS.md`

All `PWC-` rows, their evidence classes, and that document's §9 correction log. Its
§7 records what it deliberately did not cover; those exclusions are
scope fences here (§6), not gaps for the round to fill opportunistically.

### 1.3 The papers corpus

**The corpus is complete, versioned, and separately pinned.** It lives in the
`shekyl-dev` sibling repo at `docs/papers/` — not in `shekyl-core`, which is
why the `dev` sha above does not cover it. It is **tracked git content, not a
scratch directory**, so it pins cleanly:

> **Corpus pin:** `shekyl-dev` @ `4cabe8ef2e86b2cb8f0d202549dc74dd3c28c81e`
> (branch `dev`, verified pushed via `git ls-remote origin dev`). All ten items
> below are tracked at that commit.

An earlier draft called this "a local reference corpus, not versioned" — true
of *this* repository and misleading everywhere else. The correction matters
because it turns an unreproducible claim into a checkable one: **"complete" and
"ten items" are now assertions about a named commit** rather than about one
workstation. Every claim drawn from a paper is additionally cited to a section,
so it survives even if a reader has a different copy. Ten items at that pin:

`wireguard.pdf` · `Bolt-08-transport.md` · `2025-95-Eclipse-Attacks-p2p.pdf`
(Shi et al., NDSS 2025) · `doubleratchet.pdf` · `2022-539_PQC_Noise.pdf` ·
`2608.00954v1_Noise_PQC.pdf` · `2504.17809v1_Levin_protocol.pdf` ·
`2509.10214v1_Levi_p2p.pdf` · `2607.07062v1_TOR_Deanonymizing.pdf` ·
`2023-423_Hybrid Signatures.pdf`.

`doubleratchet.pdf` is newly relevant: it is the primary source for PW-8's
rejected option (c), the KEM-ified ratchet, and a round revisiting that
rejection should read it rather than the register's paraphrase.

**A drafting note kept deliberately, because it is a live hazard for this
round.** An earlier version of this section reported the corpus as
*incomplete* — that was wrong. The search behind it piped a multi-path `find`
through `head`; the two files sought were results **38 and 39 of 39**, below
the cut. A truncated listing can support a positive finding but **never a
negative one**: the thing you are looking for may be under the cut, which is
exactly what happened. The round will make negative claims about the tree
(PWC-E2's absent rate limit is one), and every such claim must rest on an
unfiltered enumeration whose total is stated.

**The WireGuard citation debt is discharged**, by reading
`wireguard.com/papers/wireguard.pdf` at source. That direct read is retained as
the provenance of record because it is verifiable independently of any local
file; the corpus copy is the convenience copy. Verified, and each item
correcting the register:

| Register says | Source says | Consequence |
| --- | --- | --- |
| WG re-handshake ≈ 2.4–2.8 KB, ~15× BOLT-8 | 148 B + 92 B = **240 B**, ≈ **1.45×** BOLT-8's 166 B | §0(b). Fix on the register's first touch; never quote the old ratio |
| "WireGuard is `Noise_IK`" | `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (WireGuard paper §5.1, Construction) | Minor but real: **IKpsk2**, not plain IK. Does not disturb PW-19a's argument, which turns on the `K` pre-message, present in both |
| Option (b) carries "a cadence fingerprint requiring jitter *and* padding to suppress" | WG **already jitters**: "an additional amount of jitter is added to the expiration" (WireGuard paper §6.1) — but *to prevent two peers initiating simultaneously*, not to defeat an observer | The accurate claim is that WG's jitter is **not sized for fingerprint suppression**, not that jitter is absent. State it that way or the round inherits a false premise about what (b) would cost |

Verified constants (WireGuard paper §6.1), for any row that needs them: Rekey-After-Messages
2⁶⁰; Reject-After-Messages 2⁶⁴ − 2¹³ − 1; **Rekey-After-Time 120 s**;
Reject-After-Time 180 s; Rekey-Attempt-Time 90 s; Rekey-Timeout 5 s;
Keepalive-Timeout 10 s.

**Standing instruction:** any figure quoted into `SHEKYL_P2P_PROTOCOL.md` must
be traceable to a source read in this round or a prior one that named its
verification.

### 1.4 PW-3 / PWC-X7 — **debt discharged, and the finding is worse than recorded**

The census recorded PW-3's attribution as unverifiable from the repository:
true of `shekyl-core`, false of the corpus. Now closed, from the paper's own
prose rather than from any figure read.

**The right figure is 4(c), not Fig. 6.** Figure 6 is *"Public key and
ciphertext sizes for DH and ML-KEM"* — primitive sizes. The per-pattern
handshake totals are **Fig. 4(c), "Message overhead per handshake"**, chart
title *"Handshake Message Overhead: Bytes per Handshake"*, y-axis *"Total
Bytes Exchanged"*, x-axis groups **NN / XX / IK / KK** left to right.

**And PW-3's headline number belongs to the wrong pattern — the register's own
caveat was right.** NoisePQC++ §6.2(e) states it in prose, which is authoritative over any
bar read:

> PQ patterns incur 28.6–46.8× more wire overhead than classical, with KK
> highest because its classical baseline is very small… HFS grows less than
> pure PQ in multi-message patterns (e.g., **XX: HFS 14.4×** vs. PQ 36.1×)…
> **NNhfs is the exception at 33.0× because classical NN starts from only 80
> bytes.**

| | classical | HFS ratio |
| --- | --- | --- |
| **NN** — Shekyl's pattern | **80 B** | **33.0×** (≈ 2.6 KB) |
| XX | 192 B | 14.4× |

**These are whole-handshake totals, both directions — not first-flight
figures**, and the distinction matters to what a classifier keys on. Fig. 4(c)'s
y-axis is *"Total Bytes Exchanged"*, and HFS deliberately splits the KEM
material across two messages: `e1` carries the initiator's secondary ephemeral
ML-KEM public key (1184 B) and `ekem1` carries the responder's encapsulation
ciphertext (1088 B). So the **first message** is roughly `e` + `e1` ≈ 1.2 KB and
the second roughly `e` + `ekem1` + tag ≈ 1.1 KB; the ≈2.6 KB is their sum plus
framing. A passive classifier bucketing on the opening message sees ~1.2 KB, not
~2.6 KB. Nothing in §1.4's conclusion turns on which is used — both are
constants — but a spec that quotes the total as a first-flight size would be
wrong by about 2×.

So the register's "~14× classical→hybrid" is **XX's** figure and its 192 B is
**XX's** baseline. PW-3 suspected exactly this ("extracted adjacent to the NN
pattern's row, not confirmed against XX") and was correct. **For the NN-family
gossip lane the multiplier is 33.0×, not ~14×** — more than double what the
register records, because NN's classical baseline is the smallest of the four
and the KEM material is a constant added to it.

**PWD-T2 stays load-bearing, but the ratio is the wrong lens — and the round
must not inherit the alarm.** 33× is striking as a *ratio* and unremarkable as
an *absolute*, because Shekyl's baseline is enormous by cryptocurrency
standards; that is what FCMP++ plus hybrid PQC costs. Measured against what
this system already moves (all verified at the pin):

| | bytes | source |
| --- | --- | --- |
| Hybrid `NN` handshake, **whole handshake, both directions** | ≈ 2,600 (inferred) | §1.4 above — PWD-T2 to pin |
| **Carrier window** — the padding quantum already in production design | **20,480** | `params/carrier.rs` `WINDOW_BYTES` |
| Structural max transaction (8-in/16-out at `MAX_TREE_DEPTH`) | 97,964–97,969; **98,046** with the Levin envelope | `carrier.rs`, `MAX_FRAGMENTS` derivation |
| PQC hybrid single key, **per input** | 1,996 | `cryptonote_config.h` `PQC_HYBRID_SINGLE_KEY_LEN` |

The whole hybrid handshake is **about one-eighth of a single carrier window**,
and smaller than the PQC key material of a two-input transaction before a
single proof, output or signature byte is counted.

**But the cost framing is not the question, and PW-3's answer does not survive
examination. PWD-T2 must not pin a band.**

The handshake's *existence* was never hideable: a TCP SYN, then bytes, then a
session, is visible at the packet layer. **The asset is protocol identity** —
not "an encrypted connection was opened" but "a handshake *for what*." A censor
acts on the second. That splits PW-3's single requirement into three claims
that need separate answers:

**(i) No magic constant — PW-9 stands, unchanged and independently.** An 8-byte
constant at offset 0 of every connection answers "for what" with **one 8-byte
comparison**, needing no decryption and no connection state. Removing it is cheap and unambiguous. **But it must not be allowed
to carry an anonymity claim:** it raises the cost of *bulk passive scanning* —
sweeping traffic for a known prefix — and does nothing against *targeted active
probing*, which is the attack in (iii). Keep it as a hard requirement (PWD-T5),
stated for what it buys.

**(ii) The size fingerprint cannot be padded away, and padding would
manufacture the signature it claims to remove.** Two reasons, the first
verified at our own source:

- **The flight is already constant-size by construction.** `NN`+hfs has no
  variable-length component: `ML_KEM_768_EK_LEN = 1184`,
  `ML_KEM_768_CT_LEN = 1088`, `X25519_KEM_CT_LEN = 32`
  (`rust/shekyl-crypto-pq/src/kem.rs`), no statics, no variable payload, fixed
  AEAD tags. **Every Shekyl handshake is already the same number of bytes.**
  There is no variance for padding to remove — padding changes *what the
  constant is*, not *whether one exists*.
- **A constant is precisely what a classifier wants.** "Every connection whose
  first message is exactly N bytes is Shekyl" is a perfect signature. PW-3's
  phrasing — a band "independent of pattern/KEM in use" — was written to stop
  an observer distinguishing *between configurations*. **Shekyl ships one
  configuration.** There are no configurations to tell apart, so the
  requirement solves a problem this deployment does not have while leaving the
  actual signature untouched.

What the 33× told us is that the flight is *distinctive* (2.6 KB where classical
`NN` is 80 B). It never told us padding fixes that. Turning a distinctive
constant into a differently-sized constant is relabeling, not obfuscation.

**(iii) On clearnet, protocol identity is undefendable by construction — and
this is a ruling, not an open scope question.**

The decisive argument is not about traffic shape at all: **on clearnet your IP
is known, so anyone may dial your node and see whether it completes a Shekyl
handshake. If it handshakes, it is Shekyl.** No passive obfuscation touches
this, because the adversary is not observing — they are *participating*. Even a
perfect padding or mimicry scheme is defeated by a single connection attempt.

**It composes directly with PW-19a, and that is what makes it structural rather
than a cost trade.** The no-authentication constraint means anyone can be your
peer by dialing in; that is the design of an open gossip network, not a
weakness in it. But a node cannot simultaneously **accept connections from
strangers** and **conceal that it accepts them**. The two are the same fact
viewed from opposite ends.

This also disposes of the pluggable-transport escape. obfs4 and Shadowsocks
fight active probing with **authentication tokens the prober cannot produce** —
only a peer holding a pre-shared secret gets a response. That is precisely the
out-of-band prior knowledge PW-19a forbids. So probe-resistant clearnet gossip
is not merely expensive; **it is incompatible with the no-authentication
invariant.** Mimicry would make Shekyl traffic *look* like TLS to a passive
observer and would still answer a prober.

**A second, independent impossibility, and it is worse: discoverability.** A
public gossip network must have dialable peers — nodes advertise addresses so
strangers can reach them. The adversary therefore does not even need to guess
which IPs to probe: **the protocol hands them the target list.** Levin
volunteers up to 250 peer entries per handshake and again per timed-sync
(PWC-D1, PWC-B4, PW-16), so one honest connection yields a candidate set.
Discoverability and clearnet node anonymity are mutually exclusive for the same
reason a phone book defeats an unlisted number — and note this leg survives
even if the probe leg were somehow answered, because it attacks *enumeration*
rather than *identification*.

**Ruling (Rick, 2026-09-01) — the posture, restated:**

| | clearnet | Tor |
| --- | --- | --- |
| **Encryption** — confidentiality and integrity against the path observer | **yes**, and it is the transport's job | yes |
| **Anonymity** — concealing that this IP runs a Shekyl node | **no. You are not anonymous as a node.** | **yes(ish)** — the onion address replaces the IP, and *is* a public key, so the endpoint is self-authenticating (PW-19a's own consequence) |

**Therefore Tor is the recommended transport, and the installed default once
that lane lands.** This is consistent with what is already in the tree: the
Q12-D6a ruling records that a node "routes clearnet, which exposes its IP as a
relay source", and rejects reading (a) precisely because "the operator who
configured Tor to avoid IP exposure still gets it".

**That half of the ruling is a product commitment, and it binds a lane this
round does not own.** "Installed default" is a UX obligation, not just a
routing preference: under
[`81-no-protocol-knowledge`](../../.cursor/rules/81-no-protocol-knowledge.mdc)
a user must not need to know what Tor *is* to get the property, and under
[`80-usability`](../../.cursor/rules/80-usability.mdc) the default is what most
users will actually run. It reaches the **Tor / P-transport lane** as
**ratified ground for its next brief** — bundled installation, default-on, and
the failure modes that follow when the bundled Tor cannot start
([`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc)) are that
lane's to specify, not P2P-2's to design. Recorded here **so it is inherited
rather than rediscovered**; see §6's fences.

**The owning document is updated in this same change, not left to contradict
this one.** [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §6.5 said Tor
was "**not** frozen as the principal default", which this ruling reverses; two
design documents giving opposite status to the same default is worse than
either being stale, because whichever a reader reaches first is authoritative
to them. Its §6.5 now carries the ruling, following the same discipline PW-26
already imposes on Q-10 — *the document that declared the dependency records
its discharge; do not let this be a one-way read.*

**What was deliberately left open there:** §6.5's pending decision is **embed
Arti vs. drive an external Tor gateway, and how either is surfaced in the
wallet UI/UX.** The ruling settles the *posture*, not the *mechanism*, and that
question stays with the Tor/P-transport lane. Also recorded at that document:
the recommendation no longer waits on the clearnet↔Tor measurement it set up,
because "clearnet cannot provide anonymity" is a structural result about active
probing that no delta measurement could have produced — the measurements remain
valid for what Tor buys against the *passive* supernode adversary.

**What this closes and what it does not.** It closes (iii) — clearnet DPI
resistance is **out of scope for anonymity**, because it is unachievable while
accepting inbound connections, and the answer to "I need my node hidden" is Tor
rather than a better clearnet disguise. It does **not** weaken encryption on
clearnet, which defends a different asset against a different adversary and
stays a hard requirement. And it does not make the Tor lane a place to do
better clearnet obfuscation: the Tor lane is the *alternative to* clearnet, not
a wrapper that rescues it.

**It reopens nothing.** `DAEMON_RELAY_PRIVACY.md` §12.10's admission rules were
already transport-blind;
PW-19a already conceded the counterparty. This adds the third leg to a stance
that was two-thirds built: **the path observer gets confidentiality on
clearnet, the prober is conceded there, and anonymity is relocated to the
transport that can actually deliver it.**

**The check that stops this being re-derived.** PW-19a's own text records the
no-authentication constraint as having been re-litigated at least three times —
it killed persona-identity-as-admission-signal (PW-21) and address/subnet/ASN
admission (`DAEMON_RELAY_PRIVACY.md` §6.10), and Q12-D6a rejected identity-as-signal twice more. The
padding requirement is the next instance of the same shape, and the pattern is
consistent enough to state as a test:

> **Any mechanism that would let a node distinguish a legitimate peer from a
> prober requires prior knowledge of that peer, and prior knowledge is
> forbidden by PW-19a.**

Check a proposed mechanism against that sentence *before* costing it. It
disposes of probe-resistant transports, admission whitelists, and — as here —
handshake obfuscation, without needing to re-derive the argument each time from
whatever figure prompted it.

**Why this had to be caught before PWD-T2 and not after.** Pinning a band would
encode a defence that does not defend, and it would then read as green forever
— a rule-47-shaped outcome, from a requirement the register itself wrote. A
padded flight is exactly as classifiable as an unpadded one; the only thing the
band changes is the number in the classifier's rule.

**That scope question is RULED, not open** — see (iii) below. Clearnet DPI
resistance is out of scope for anonymity because it is unachievable while
accepting inbound connections; the fingerprint is conceded and PWD-T2 reduces to
(i) plus the concession record. **The round must not reopen it by picking a
band.**

Two notes retained from the cost analysis, now serving a narrower purpose:
the carrier comparison establishes that padding is *architecturally normal*
here (so cost was never the obstacle — it just is not the remedy), and
`carrier.rs` remains the **template for any constant this round does pin**:
derivation written out, alternatives rejected on record, and
`tests/carrier_window.rs` asserting the derivation as an *equality* rather than
the value — its own words, *"the derivation is enforced, not performed… neither
is a literal the test could agree with by construction."* `WINDOW_BYTES`' doc
notes the inherited 3 KiB window "was a Monero cadence artifact" with no
derivation; that is the failure mode any pinned constant must avoid.

**Template for PWD-T2, and the round should be pointed at it explicitly.**
`rust/shekyl-relay-privacy/src/params/carrier.rs` is a working example of
exactly this deliverable: a size constant with its derivation written out
(`MAX_FRAGMENTS = ceil(S_max / WINDOW_BYTES) = ceil(98_046 / 20_480) = 5`), the
rejected alternatives on record (the inherited 20, and why an epoch-ceiling
coincidence is not a derivation), and `tests/carrier_window.rs` **asserting the
derivation rather than the value** — its own comment: *"the derivation is
enforced, not performed… neither is a literal the test could agree with by
construction."* A one-sided bound would have gone green on the wrong number;
the equality is what makes it a check.

Two constraints on use: the ratio and the 80 B are quoted from the paper's
prose and are safe; **the absolute HFS byte count (≈ 2.6 KB, consistent with
33.0 × 80 B) is inferred and must be pinned from the table or a
higher-resolution read before it enters normative text.** And note this closes
a loop with §0(b): PW-8's "2.4–2.8 KB" is a plausible *absolute* NN-hybrid
handshake size — what was wrong there was comparing it against BOLT-8's
*classical* 166 B, not the magnitude itself.

### 1.5 What option (a)'s zero-byte rekey buys — a privacy argument, not a cost one

PW-8's ruled mechanism costs **nothing on the wire**: `ck', k' = HKDF(ck, k)`
plus a nonce reset, per direction, both sides deriving from state they already
hold. Nothing is transmitted, so there is nothing for an observer to see and
nothing to pad. **The ≈2.6 KB flight is paid once per connection, at setup, and
never again for that connection's lifetime.** Two consequences belong on the
record.

**This is retroactively the strongest argument against option (b), and it is a
privacy argument.** A WireGuard-style periodic re-handshake would not merely
have cost bytes per interval — it would have **re-emitted the classifiable
flight on a schedule**, which is both a repeated DPI opportunity and a cadence
signal in its own right, the PW-28 hazard arriving by a second route. Option
(a) reduces the handshake's observable footprint to the theoretical minimum:
**exactly one event per connection.** That is cleaner than the cost argument
the row currently carries, and it should be folded into PW-8 as the rationale
for (a) at the register's next touch.

**Handshake exposure is therefore a function of connection lifetime, which ties
PW-3 to PW-23.** If connections churn, the classifiable event recurs; if
work-based tenure keeps outbound relationships stable across long intervals, a
node's handshake count tends toward *the number of distinct peers it maintains*
rather than scaling with time. So the tenure mechanism **materially reduces
PW-3's exposure frequency** — a peer relationship lasting hours amortises one
flight to nothing. That composition was invisible while the two rows were
reasoned about separately, and for once it runs in the helpful direction. It is
noted on PWD-I3.

**What it does not do is rescue padding.** An earlier statement of this
analysis closed with "padding is still required"; **that is retracted by §1.4**
— one classifiable event per connection is still classifiable, and padding does
not make it less so when the flight is already a constant. Rotation being free
bounds *how often* the event appears. It does not change *what the event looks
like*, and nothing in this section should be read as reinstating the band.

---

## 2. The deliverable

`docs/design/SHEKYL_P2P_PROTOCOL.md` — a **normative specification**, organised
by the four clusters below, with a **wargame table per decision**. Each
decision carries: the options considered, the adversary and channel each option
answers (per the threat-model discipline: name `T` and its channel or there is
no threat model), what is conceded, and the falsifier that would reopen it.

**The falsifier is a gate, not advice** (ruled by steering 2026-09-01). A
decision without one is not ruled; it is deferred with extra words. This is
[`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
applied to design decisions — reject-now-with-reopening-criteria, rather than
pre-provisioned flexibility.

**Definitional note, so the gate stays satisfiable without being watered
down.** Not every decision has an experiment to run. For a **value choice**
— a constant, a limit, a cadence — the falsifier is a **named reopening
criterion**: a concrete future observation that would reopen the decision.
"Reopen if measured p99 handshake latency on the Pi-4 floor exceeds X" is a
falsifier; "reopen if this turns out to be wrong" is not. The test is whether
a future reader could recognise the triggering observation without having to
re-derive the decision.

### 2.1 Cluster T — the transport, concrete

Converged inputs: pattern (`NN`-family, PW-19a), PQ mechanism (HFS hybrid,
PW-7b), implementation path (native over `shekyl-crypto-pq`, PW-7a). What
remains is to make them concrete and normative.

| id | Decision | Grounded in |
| --- | --- | --- |
| PWD-T1 | The exact handshake: token sequence, `ck` derivation, where the ML-KEM shared secret is mixed | PW-1, PW-2, PW-7b |
| PWD-T2 | **PW-3 is retired as written — do NOT pin a padding band.** §1.4: the flight is already constant-size, so a band relabels the constant; and clearnet protocol identity is undefendable against active probing, which no passive defence touches. **RULED (Rick, 2026-09-01): clearnet gives confidentiality and integrity, not anonymity; anonymity is Tor's, and Tor is the recommended/default transport.** The round records the concession and its impossibility argument — it does not re-derive a band | PW-3 as retired in §1.4; PW-19a; `carrier.rs` is the template for any constant the round *does* pin |
| PWD-T3 | Rekey: BOLT-8-style `ck', k' = HKDF(ck, k)`, per-direction, nonce reset — **zero bytes on the wire**, both sides deriving from state they already hold | PW-8 (ruled; carry the §0(b) correction **and the §1.5 privacy rationale**) |
| PWD-T4 | **`e1`/`ekem1` semantics written normatively in `SHEKYL_P2P_PROTOCOL.md`** — the round's deliverable, not this brief — with `noise_hfs_spec` cited as provenance only | **PW-7c** |
| PWD-T5 | Wire prefix: what replaces `LEVIN_SIGNATURE`'s fixed 8 bytes | PWC-A1, PW-9 |
| PWD-T6 | Packet limits derived from largest legitimate message, replacing two inherited and disagreeing constants | PWC-A5, PWC-F3, PW-10 |
| PWD-T7 | Whether compression survives, and if so its position relative to encryption | PWC-A10 (recorded as **conditional**, not a present defect), PW-13 |
| PWD-T8 | KAT strategy — Shekyl mints its own; **PW-7d's differential-partner option is recorded, not decided** | PW-6, PW-7d |

### 2.2 Cluster B — behavioral commitments

The cadence, limit and drop behavior the census enumerated. Most of the
bucket-4 mass lives here.

| id | Decision | Grounded in |
| --- | --- | --- |
| PWD-B1 | Rate limiting on handshake / timed-sync / ping — currently **absent** | PWC-E2, PW-15 |
| PWD-B2 | Cadence jitter — currently **absent**; a distinct fix from PWD-B1, and neither substitutes for the other | PWC-E1, PWC-E3, PW-28 |
| PWD-B3 | Per-command caps: derive them, and decide the unknown-command fallthrough that currently reaches `size_t::max` | PWC-C7 |
| PWD-B4 | Unknown flag bits: reject at ingress, or keep accepting | PWC-A6 / **PWC-A6a** (the codec accepts them; no relay carries them today) |
| PWD-B5 | `return_code` on notifications — inherited RPC-over-Levin affordance | PWC-A7, PW-12 |
| PWD-B6 | The two block-propagation paths (2001 alongside 2008) — collapse or keep, on a chain with no fluffy transition | PWC-C3, PW-27 |
| PWD-B7 | Drop semantics: `drop_connections`-by-host, the score floor, and whether the **inherited** no-drop-offense set is adopted deliberately | PWC-E7, PWC-E8, PWC-E9 |
| PWD-B8 | Dead surface: the two lineage-dead structs and the never-driven 43-second timer | PWC-F1, PWC-F2, **PWC-E4a** |
| **PWD-B9** | **Outbound connection diversity: a same-host cap on outbound slots.** Added 2026-09-02 by PWD-I1's amendment, which removes `peer_id` from the wire and needs this as the replacement for id-based duplicate avoidance. **No pre-existing B row covered outbound selection** — B1 is command rate limiting, B7 is *drop* semantics — so routing to "cluster B" had no owner. Note the list asymmetry it must handle: the white list already holds one entry per host via `evict_host_from_peerlist`; the **gray list does not**, so the amplifier runs through gray draws | PWD-I1, PWC-E11, `net_peerlist.h:374` |
| **PWD-B10** | **Delete the back-ping and `COMMAND_PING` (1003) from the wire surface.** Added 2026-09-02 and **answered the same day by PWD-I1's consumer inventory**, so this row carries an execution, not an open design question: `try_ping` has one caller whose callback is the whitelist promotion PWD-I2 forbids, and `try_ping` is `COMMAND_PING`'s only invoker. Four p2p commands become three | PWC-D11, PWD-I1, PWD-I2 |

### 2.3 Cluster I — identity and Sybil resistance

| id | Decision | Grounded in |
| --- | --- | --- |
| PWD-I1 | Session identity: fully ephemeral, no durable peer id on the wire | PW-19, PW-19a, PWC-D4 |
| PWD-I2 | Peerlist disclosure: size, anonymisation, and whether both handshake and timed-sync carry it | PWC-D1, PWC-D2, PWC-B4, PW-16 |
| PWD-I3 | Tenure recognition: address-keyed, never a wire field; **and the `first_seen` ordering that decides which anchors take the slots**. Composes with PW-3: stable tenure **amortises handshake exposure** (§1.5) | PW-17, PW-18, PWC-D5, `P2P_1_WIRE_CENSUS.md` §5.4 |
| PWD-I4 | **Specify `ρ` / `g_max`** — the work-based admission and eviction mechanism | PW-23, PW-25 |
| PWD-I5 | **Close Q-10 across documents**: update `DAEMON_RELAY_PRIVACY.md` itself to record the resolution | **PW-26** — a one-way read is not closure |
| PWD-I6 | The Shi et al. residue: graylist and whitelist sub-attacks, both **unaddressed** | `P2P_1_WIRE_CENSUS.md` §5.2, PWC-D3, PWC-D10, PWC-D11 |

### 2.4 Cluster A — the archival submission-path gap

| id | Decision | Grounded in |
| --- | --- | --- |
| PWD-A1 | Does the archival firewall / P-transport design cover the **serve-credit submission** path, or only serving? | PW-22, PWC-X5 |

The census narrowed this from "is there a leak" to a falsifiable claim:
production submission runs through the `Local` posture, and **no production
caller selects the per-`P` `OwnRemote` arm**. Name such a call site and PWD-A1 is
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
| **Absorbed** | A protocol decision subsumes it | The `PWD-` id that absorbs it |
| **Deferred** | Not settled in this round | A **named blocker** and the owner — per rule 22, a deferral without a named blocker is not a deferral |

The round's own arithmetic must close, in its closing section:

```text
ruled + absorbed + deferred = 46
```

`PWC-X` rows carry no bucket and are excluded, as they are from the census
totals. Bucket-3 rows (PWC-F1, PWC-F2) are already dispositioned as deletion
candidates and route to the p2p lane — they are **not** RK-cutover residue; the
census's §9 records the provenance correction and why the routing changed.

**Also owed at close:** every `PW-` and `PWC-` row that a decision touches gets
a pointer back to the `PWD-` id that settled it (steering requirement 7). A
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
- **The Tor lane's UX is out, but its ground is now fixed.** Rick's ruling
  (§1.4(iii)) makes Tor the recommended transport and the installed default.
  Bundling, default-on and the cannot-start failure modes belong to the
  Tor / P-transport lane; P2P-2 neither designs them nor re-opens them.
- **No implementation.** P2P-3.

---

## 7. Rider — the register's next edit

> **GATE CLEARED 2026-09-01 — this section is now a record, not an obligation.**
> All four corrections landed in the register (PR #593), so **P2P-2 is no longer
> blocked on them**: PW-3 is retired as a requirement and kept as a conceded
> property with corrected figures, PW-3a carries the clearnet/Tor posture
> ruling, PW-9 is scoped, PW-8's WireGuard figures are corrected at primary
> source with option (a) re-grounded on privacy, PW-19a gains the reusable
> prior-knowledge check, and PW-25's pointers are fixed. Swept here by the PR
> that cleared the gate, per the index's own method note: *"the cleared-gate
> sweep is a landing obligation of the PR that clears the gate, not of the docs
> that name it."* Blocked-when-actually-unblocked is the expensive direction —
> nobody re-checks a gate that says it is closed.

The deferral as it was disclosed at the time, retained because the reasoning is
the record of why these did not ride in the brief's own PR:

- **Blocker (discharged):** the register is a separate document with its own validation surface and its own steering review (rule 19). Folding four corrections — one of which **retires a requirement** and adds a posture row — into a dispatch-brief PR would have buried the brief under an edit needing review on its own terms.
- **Owner:** this session.
- **Schedule (met): before the P2P-2 round dispatches**, which was a hard ordering rather than a preference. The round *reads the register*; had it still carried PW-3's padding requirement and PW-8's wrong figures at dispatch, it would have inherited a retired requirement and a mis-stated ratio.

The four corrections, **all landed**:

1. **§12.11 / `ρ` citation decay.** `DAEMON_RELAY_PRIVACY.md` §12.11's body is
   **superseded in part** by two banners (the Exploit tier is deleted; the live
   mechanism is a uniform random draw over the non-cooled admissible set,
   that document's §§52/53/54). And `ρ` is **not mentioned in its §12.10 at all** — the canonical
   statement is that document's §13.5. PW-25's claim survives; its pointer does
   not. PWD-I4 and
   PWD-I5 must read the live text, not the superseded body.
2. **PW-8's WireGuard figures** — §0(b) and §1.3. The ruling stands; the
   ratio, the pattern name and the jitter claim do not. Add §1.5's zero-wire-
   bytes rationale as the **privacy** ground for option (a): (b) would
   re-emit the classifiable flight on a schedule, which is PW-28 arriving by a
   second route.
3. **PW-3 retired as written, and a new posture row.** Three edits:
   - **PW-3** — replace the padding requirement with a **conceded-property**
     statement: clearnet node identity is not defendable against active
     probing; padding cannot fix it; obfuscation-token mechanisms are
     unavailable under PW-19a; anonymity is owned by the Tor lane. **Keep the
     33.0× / 80 B figures as recorded fact** — they are true, they simply do
     not imply the requirement that was derived from them.
   - **PW-9** — survives independently, but must not carry an anonymity claim.
     It raises the cost of bulk passive scanning; it does nothing against
     targeted probing.
   - **New posture row** — the clearnet/Tor split as a ruling *with its
     impossibility argument attached*, so a future round cannot re-derive
     "we should pad the handshake" from a fresh reading of the multiplier.
     Carry §1.4's PW-19a check verbatim into that row; it is the reusable
     part.

---

## 8. What this brief does not do

It does not rule any bucket-4 row, choose a handshake, specify `ρ`, or resolve
PW-22. Those are the round's, and a brief that pre-empted them would be the
round happening in the wrong document with no wargame record.

It also does not re-open the invariants in §3. If the round finds one of them
untenable, that is a finding to raise with steering explicitly — not a decision
to take inside a cluster.
