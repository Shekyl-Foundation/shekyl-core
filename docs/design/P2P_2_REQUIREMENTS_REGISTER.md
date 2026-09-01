# P2P-2 requirements register

**Status:** Steering-reviewed 2026-08-31 — sound, spot-checked (four
`drop_connections` sites and §12.10's framing independently confirmed),
ready to land as a tracked doc. Four deltas from that review are folded in
below (PW-3 correction, PW-22 rewrite, PW-27, PW-28). **Second round folded
2026-08-31:** §1 threat-model framing added; PW-8 ruled (option (a), PCS
not required for gossip) with two BOLT-8 spec corrections from a
primary-source read; PW-19a added recording the standing no-authentication
constraint; PW-23a added as its implementation rider. **Third round:**
PW-19a's citation task closed (three jointly-entailing rulings located and
cited); PW-22 narrowed to a coverage gap check on the strength of the
verified `derive_socks_user` per-persona isolation. **Fourth round:** PW-19a
gains the `XK`/`IK`-are-inapplicable-not-rejected explanation (Noise pattern
letters, the `K` pre-message, why authentication needs an out-of-band trust
anchor gossip peers lack); PW-8 gains the pattern-transferability paragraph
(`ck` rotation is framework-level and transfers to `NN`; the authentication
context does not and is conceded). **Fifth round, 2026-09-01 — the
implementation-path round:** `snow` evaluated at source and ruled
read-not-depend (PW-7a), with the finding that **it already has HFS**, so the
question was never "convert it for PQC" but "swap which KEM it uses" — and
`KemChoice` being a closed single-variant enum makes that a fork. PW-7b rules
that **HFS suffices for `NN`**, which moots PW-5 and discharges PW-4 for the
gossip lane, because the PQNoise machinery those rows describe exists to make
*authentication* post-quantum and `NN` has none. PW-7c rules the hybrid
handshake's semantics **normative in Shekyl's own protocol text**, since a
genesis-frozen wire cannot cite a mutable draft as authority — which turns
the draft's instability from a risk into an argument for the native path.
PW-7d parks snow-as-test-only-differential-partner as a rule-17 wargame
question for P2P-3. **Sixth round, 2026-09-01 — the corrections round, run
against the P2P-1 census and primary sources before P2P-2 dispatches, because
the round reads this document:** **PW-3 is RETIRED as a requirement** and
becomes a conceded property (its 33.0× / 80 B figures corrected and kept as
fact — the ~14× and 192 B were **XX's**, and both are whole-handshake totals,
not first-flight); **PW-3a** minted as the posture row carrying Rick's ruling
that clearnet gives confidentiality and integrity but **not anonymity**, with
the two independent impossibility arguments; **PW-9** survives but is barred
from carrying an anonymity claim; **PW-8's** WireGuard figures corrected at
primary source (1.45× not ~15×, `IKpsk2` not `IK`, jitter present but not
sized for suppression) and its option-(a) ruling re-grounded on **privacy**
rather than cost; **PW-19a** gains the reusable prior-knowledge check; and
**PW-25's** pointers corrected (`ρ` is §13.5, not §12.10; §12.11's body is
superseded in part). Sequencing ruling:
this lands first as its own docs PR with `PW-` registered in the index at
birth (rule 94 §1); P2P-1 (the wire census) is the next artifact and absorbs
§7's open tasks as census work rather than a separate errand. This is not
the P2P-2 dispatch brief; it is the durable input the brief gets drafted
from, so the rows below survive independent of any one chat transcript.

**Pinned:** `dev` @ `ab3cc98e6eb73db2b309730ccc9853ba4ea95e7d` (fetched fresh,
verified against `git ls-remote origin` at time of writing — 2026-08-31).
Every source claim below was read at this sha; re-verify before drafting the
brief if `dev` has moved.

**Identifier family:** `PW-` (P2P wire), checked unique against the index's
existing families (CW/VG/SH/CT-ACT/PC/RF/SO/CR/CB/F-D/…) — no collision.
Register at birth (rule 94 §1) when this lands as a tracked doc.

**Scope boundary, ratified by prior work, verified this session:**
`RPC_TRANSPORT_POSTURE.md` §2.1 (`:99-106`) — "P2P is not RPC... RPC is
operator-to-operator; P2P is adversarial by design and hardened separately."
RT-4's pinned-mutual-TLS mechanism (`:223-227`, "No CA... every client is a
device the operator physically holds — there is no delegation, only
enrolment") is therefore **not transferable** to P2P by default; P2P's peer
is a stranger by construction, so any borrowed mechanism needs its own
justification, not RT-4's.

**Row-editing convention (added 2026-09-01, after the same defect twice).**
Several rows here are **multi-claim objects** — PW-8 alone carries a ruling, a
mechanism, four rejected options with figures, a pattern-transferability
argument and an evidence cell. **Fixing a row's headline does not sweep its
body.** When any claim in a row changes, **grep the whole row for that claim**
before considering the edit done.

The rule exists because it was learned twice in one session, both in PW-8: the
headline ratio was corrected while the evidence cell still read *"not
re-verified at primary source"*, and the options list was corrected to
`Noise_IKpsk2` while the transferability paragraph a few hundred words later
still said `Noise_IK`. Both would have survived a reviewer checking the
sentence that was reported as fixed.

**Sibling unit rule, same origin.** A **benchmark total is not a wire event.**
PW-3's 33.0× and ≈2.6 KB are *whole-handshake totals across both directions*;
because HFS splits the KEM across messages (`e1` initiator, `ekem1` responder),
the opening message is ≈1.2 KB. Any per-message figure must be derived from the
**token layout and our own constants**, never by relabelling an aggregate a
paper reports. Three separate errors were made on this one number —
attribution (XX's row read as NN's), instrument (a bar read where the paper
states it in prose), and unit (aggregate quoted as a wire event) — which is why
it is written down rather than remembered.

---

## 1. Transport — hybrid-PQ Noise, working assumption

**Threat model for the transport layer (framing — decides what the transport
is and is not accountable for).** The transport's adversary is the
**non-participant path observer**: ISP, backbone, censor, anyone on the wire
who is not an endpoint. **The counterparty is conceded**, under the standing
no-authentication constraint (see PW-19a): on an open gossip network anyone
can be your peer by dialing in, and every relay sits between an origin and
the network by construction — being "in the middle" is the job description,
not an attack. The concession is precise, and the precision is
load-bearing:

- **Content is public by design.** Blocks, transactions, serve-credit vins
  with `P_canonical_id` in the clear — a recording peer learns nothing here
  that a block explorer doesn't publish. Defending this would be incoherent.
- **Arrival metadata is not public by design.** The tuple `(transaction,
  arriving connection, timestamp)` exists only at the relay layer, is never
  in a block, and is the input to origination linkage. This is D++'s scope,
  and per §12.10 it is **taxed, not eliminated** — an adversary holding a
  share of connections gets a partial view, and the mechanism raises its
  cost rather than closing it.

Do not compress this to "recording peers see only what's public anyway" — a
future reader who accepts that framing will ask why D++ is being paid for at
all, and the stem-phase properties get weakened on a false premise.

**Two properties drop out as non-requirements for the same reason** (both
are properties *about the counterparty*, and the counterparty is conceded):
**authentication** (PW-19a) and **post-compromise security** (PW-8). What
remains as the transport's actual job, against the path observer:
indistinguishable-from-random on the wire (PW-3, PW-9), forward secrecy
against recorded ciphertext (PW-8 option (a)), no covert channels (PW-11),
no linkable identifiers (PW-19). **The transport must never be asked to
carry a privacy property that belongs to D++ or the cover-traffic layer** —
the ProxyMark lesson pointed the other way: the layers must compose, and
each must own its actual scope.

**Consequence of PW-7b, recorded here because it narrows this section's own
scope.** Forward secrecy against recorded ciphertext is the *only* PQ property
this list asks of the transport, and HFS delivers exactly that — an ephemeral
KEM alongside the DH, defending the recorded-traffic adversary named above.
The heavier PQNoise apparatus (`skem`, the static-static translation, PW-4's
ephemeral-dual-use caveat, PW-5's extra round trip) exists to make
**authentication** post-quantum, and authentication is the property §1 already
concedes. So the two caveats that looked like open transport risk were
artefacts of a pattern Shekyl is not using: **`NN` has no statics, therefore
no static-key DH to replace, therefore nothing for that apparatus to do.**
The implementation path follows from the same fact — native over
`shekyl-crypto-pq` (PW-7a), with the construction normative in Shekyl's own
text (PW-7c).

| ID | Finding | Evidence | Status |
| --- | --- | --- | --- |
| PW-1 | Hybrid Noise (classical DH + ML-KEM, HFS patterns) has a generic computational security proof (fACCE model) for confidentiality/authenticity, matching or exceeding classical Noise's per-pattern proofs. | `2022539_PQC_Noise.pdf` (Angel/Dowling/Hülsing/Schwabe/Weber, CCS 2022) | Grounded — not a novel/unanalyzed composition |
| PW-2 | Official HFS composition method exists, authored by the Noise framework's own designer, with a working reference implementation covering NN/XX/IK/KK in classical, pure-PQ, and hybrid modes. | `noise_hfs_spec` (Perrin); `2608.00954v1_Noise_PQC.pdf` (NoisePQC++, QCE 2026) | Grounded |
| PW-3 | **RETIRED AS A REQUIREMENT 2026-09-01 — recorded as a conceded property.** The finding remains true and the requirement derived from it does not. **Recorded fact, corrected:** the handshake grows **33.0×** for `NN` (classical 80 B), not ~14× — that is **XX's** figure, and the 192 B is XX's baseline. This row's own caveat ("extracted adjacent to the NN pattern's row, not confirmed against XX") was right. Both are **whole-handshake totals, both directions**: HFS splits the KEM across messages (`e1` = initiator's 1184 B ML-KEM public key, `ekem1` = responder's 1088 B ciphertext), so the opening message is ≈1.2 KB, not ≈2.6 KB. **Why the padding requirement is withdrawn:** (a) the flight is **already constant-size by construction** — no statics, no variable-length component, fixed AEAD tags (`ML_KEM_768_EK_LEN` 1184, `ML_KEM_768_CT_LEN` 1088, `X25519_KEM_CT_LEN` 32) — so there is no variance for a band to remove; padding changes *what the constant is*, not *whether one exists*, and a constant is exactly what a classifier wants. (b) The band was specified "independent of pattern/KEM in use" to stop an observer distinguishing **configurations**, and Shekyl ships **one** configuration. (c) Decisively, it would not have mattered: clearnet protocol identity is undefendable against **active probing** — see the posture row PW-3a. Pinning a band would have encoded a defence that does not defend and then read green forever (rule 47 shape). | NoisePQC++ §6.2(e) prose (authoritative over the Fig. 4(c) bars); `rust/shekyl-crypto-pq/src/kem.rs`; corpus pinned at `shekyl-dev` `4cabe8ef2` | **Conceded property — owner named in PW-3a. The figures stay as recorded fact; the requirement does not.** |
| PW-3a | **POSTURE, RULED 2026-09-01 (Rick): clearnet gives confidentiality and integrity, NOT anonymity. Anonymity is Tor's, and Tor is the recommended transport and the installed default once that lane lands.** **Two independent structural arguments, either sufficient.** *(i) Active probing.* On clearnet your IP is known, so anyone may dial your node and see whether it completes a Shekyl handshake — if it handshakes, it is Shekyl. No passive defence touches this, because the adversary **participates rather than observes**, using the node's own correct behaviour against it. It composes with PW-19a: obfs4 and Shadowsocks answer probing with **authentication tokens a prober cannot produce**, which is exactly the out-of-band prior knowledge an open gossip network is forbidden. Probe-resistant clearnet gossip is not expensive — it is **incompatible with the no-authentication invariant**. *(ii) Discoverability.* A public gossip network must have dialable peers, and the protocol **hands the adversary its target list**: up to 250 peer entries per handshake and again per timed-sync (PW-16). Mutually exclusive with clearnet node anonymity for the same reason a phone book defeats an unlisted number — and this leg attacks **enumeration** rather than identification, so it survives even if (i) were somehow answered. **Reopening criterion (rule 21):** the concession is conditioned on **PW-19a holding**, and that is the only honest criterion — a criterion naming a pluggable-transport wrapper would fire on a mechanism that still answers a prober. **Product commitment carried:** "installed default" is a UX obligation under [`81-no-protocol-knowledge`](../../.cursor/rules/81-no-protocol-knowledge.mdc) and [`80-usability`](../../.cursor/rules/80-usability.mdc) — bundling, default-on, and the cannot-start failure modes ([`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc)) are the **Tor / P-transport lane's** to specify, as ratified ground rather than a rediscovery. **Not settled by this ruling:** embed Arti vs. drive an external Tor gateway, and how either is surfaced in the wallet UI/UX — still that lane's open decision. | PW-19a's three-home citation; PW-16; [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §6.5 (updated 2026-09-01 to record this ruling — the owning document records its own discharge, per PW-26's discipline); [`P2P_2_DISPATCH_BRIEF.md`](P2P_2_DISPATCH_BRIEF.md) §1.4(iii) | **Ruled. Clearnet anonymity conceded; Tor owns it.** |
| PW-4 | Ephemeral-key dual-use breaks under KEMs: classical Noise lets a peer confirm two DH results share an ephemeral share; no such guarantee exists for KEM ciphertexts. | `2022539_PQC_Noise.pdf` §2.3 | **DISCHARGED BY CHECK for the gossip lane (PW-7b)** — the check this status ordered has been run: `NN` has no static keys, so nothing in the gossip transport leans on ephemeral dual-use. Recorded as discharged rather than inapplicable, because the verification happened. Live again for any pattern that reintroduces statics |
| PW-5 | Static-static exchange has no direct KEM equivalent; the replacement (`skem` + key-confirmation message) costs a round trip. Directly relevant: RT-9-adjacent, operator-pinned patterns (KK/IK-family) rely on `ss`/`se`/`es`. | `2022539_PQC_Noise.pdf` §2.3 (translation recipe) | **Moot for the gossip lane (PW-7b)** — `NN` has no static-static exchange to translate, so the extra round trip has no subject here. **Live for the operator-pinned patterns this row already names** (KK/IK family, RT-9-adjacent): scope the cost there, not here |
| PW-6 | No standardized test-vector suite exists yet for PQNoise/hybrid patterns — NoisePQC++'s own authors generated their own deterministic vectors. | `2608.00954v1_Noise_PQC.pdf` §5.2.3 | **P2P-2 must budget minting Shekyl's own pinned hybrid-handshake KATs from scratch — no external oracle to lean on** |
| PW-7 | Rust prior art exists (Clatter) but is narrower in scope (X25519-only classical side); worth reading for pattern-encoding decisions, not depending on (no-FFI discipline). | `2022539_PQC_Noise.pdf` §2.4.1 references | Informational |
| PW-7a | **`snow` evaluated at source (v0.10.0, cloned fresh). Disposition: read, do not depend — the same treatment PW-7 gives Clatter.** The premise that snow would need converting for PQC is wrong: **it already has HFS**, behind the `hfs` feature — a `Kem` trait (`types.rs:174`), `KemChoice` in the pattern parser, the `hfs` modifier, `E1`/`Ekem1` wired into the handshake state machine (`handshakestate.rs:274-296`), `resolve_kem` on `CryptoResolver`, and `rekey_manually` / `rekey_initiator_manually` on the transport state — the exact hook PW-8's rotation would drive. **The structural blocker is that `KemChoice` is a closed enum with one variant, `Kyber1024` (`params/mod.rs:133-136`); `resolve_kem` takes that enum, so a custom resolver can supply a different *implementation* of Kyber1024 but cannot add ML-KEM-768.** That makes adoption a fork, not a resolver swap. Compounding: the backing crate is `pqcrypto-kyber` 0.8 (a PQClean C binding, i.e. FFI, where `shekyl-crypto-pq` already has ML-KEM-768 in Rust); Kyber1024 is neither the right parameter set nor the standardized ML-KEM; and HFS is a **draft** (`noise_hfs_spec` rev 1, marked unstable, not part of the Noise rev34 that snow's README tracks). Since the closed enum forces a fork either way, a fork means running an unaudited library that no longer matches upstream — inheriting neither its review nor its patches cleanly — and Shekyl's transport needs things snow does not provide anyway (PW-3's fixed-size padding band, PW-9's non-constant prefix, PW-8's directional `ck` rotation on a schedule), a native implementation over `shekyl-crypto-pq` is not much more work and is auditable as one artifact rather than as a diff against an unaudited upstream. What to take from it: the `Kem` trait as interface design, the `E1`/`Ekem1` token handling as a working HFS reference, and the pattern parser's grammar. **Verified absent from our tree: neither `snow` nor `pqcrypto-*` appears in `rust/Cargo.lock` or any manifest** — this is a candidate evaluation, not a disposition on an existing dependency, which is what makes read-not-depend the cheap default rather than a removal. | `snow` v0.10.0 read at source (feature `hfs`; `types.rs:174`, `params/mod.rs:133-136`, `handshakestate.rs:274-296`); `noise_hfs_spec` rev 1; `rust/Cargo.lock` (absence verified) | **Ruled — read, do not depend.** Two riders below |
| PW-7b | **HFS is sufficient for `NN`, which moots PW-4 and PW-5 for the gossip lane.** The PQNoise machinery those rows describe — `skem`, the static-static translation recipe, the extra round trip — exists to make **authentication** post-quantum by replacing static-key DH. `NN` has no static keys and no authentication (PW-19a), so none of it applies. The only PQ property gossip needs is **hybrid forward secrecy against the recorded-ciphertext adversary**, which is exactly what HFS delivers, against exactly the path observer §1 names. **Scope, stated the way PW-8's ruling is scoped:** gossip lane only. PW-5 stays live for any operator-pinned pattern (its own text names the KK/IK family, RT-9-adjacent), i.e. the RPC lane's question, not this one. **PW-4 is better recorded as *discharged by the check its own status ordered*** — that row said "check nothing in Shekyl's transport design leans on this property"; the check has now been run against `NN` and it does not. That is a stronger record than "inapplicable", because it says the verification happened. | This row; PW-4/PW-5 status text; PW-19a | **Ruled (gossip). PW-4 discharged-by-check; PW-5 inapplicable here, live for pinned patterns** |
| PW-7c | **The hybrid handshake's semantics are normative in `SHEKYL_P2P_PROTOCOL.md`'s own text, not by citation.** A genesis-frozen wire cannot take its authority from a mutable external draft: `noise_hfs_spec` is rev 1 and explicitly unstable, and a spec that can change under a frozen wire is not a spec the wire can point at. Shekyl's document therefore *states* the construction — token sequence, `ck` derivation, KEM placement, padding band — and cites the draft only as provenance. **This inverts PW-7a's fourth objection:** the draft's instability stops being a risk we absorb by depending on snow and becomes an argument *for* the native path, since owning the text is the only way a frozen wire gets a stable authority. Same discipline as the pinned test vectors — an external oracle that can move is not an oracle. | `noise_hfs_spec` rev 1 (unstable, not in Noise rev34); rule 30's pinned-vector discipline; PW-6 (no external KAT suite exists) | **Ruled — Shekyl's own text is normative** |
| PW-7d | **`snow` as a test-only differential partner for the classical half of the KAT suite — parked as a rule-17 wargame question for P2P-3, not decided here.** PW-6 records that no external test-vector suite exists for hybrid patterns, so Shekyl mints its own; the question is whether a `dev-dependencies`-only snow gives the *classical* half of those vectors a second implementation to differ against, the way the levin parity gate uses the C++ oracle. Arguments to weigh, not resolve: it is test-only so the no-FFI and audit objections of PW-7a bite far less, and a KAT with no independent producer is a seal rather than a check; against, it is still an unaudited dependency in the build graph, `KemChoice` means it can only ever cover the classical side, and a differential partner that cannot reach the hybrid path may create false confidence in the half that matters least. **Decide with the KAT design, in P2P-3 — a test-dependency choice made before the vectors are designed would be a decision without its inputs.** | PW-6; [`17-dependency-discipline`](../../.cursor/rules/17-dependency-discipline.mdc); the levin constant-parity gate as precedent | **Open — wargame question, owner P2P-3** |
| PW-8 | **Rekey schedule — RULED for gossip: option (a), BOLT-8-style symmetric KDF rotation. PCS is not a P2P requirement.** *Spec corrections from a primary-source read of `lightning/bolts/08-transport.md` (master): rotation fires every **500 messages**, not 1,000 — the spec rotates after 1,000 **nonce increments**, and each message consumes two nonces (encrypted length prefix + body). And BOLT-8 is not an alternative to a Noise pattern — it **is** Noise (`Noise_XK_secp256k1_ChaChaPoly_SHA256`) plus a rotation scheme, so the real axis is rekey mechanism, orthogonal to pattern choice.* **Mechanism:** `ck', k' = HKDF(ck, k)`, reset nonce to 0, per-direction (`sck`/`rck` independent). Zero wire cost, invisible to any observer, inherits the hybrid-PQ root (every rotated key descends from the ML-KEM-mixed `ck`, so HNDL/forward-secrecy survives rotation), no PW-28 interaction at all. **Why PCS is not required, on the merits rather than on cost:** PCS pays out only when an adversary obtains session keys, *loses* that capability, and the session still matters afterward. On an open gossip network the dominant adversary never attacks the session — being a peer is free, and every relay is a middle-man by construction, so stolen session keys grant a view already available by dialing in. The adversary who *does* hold keys (node owner / RCE / hypervisor) has **permanent** access, which PCS by definition cannot heal, and sees plaintext mempool and stem state regardless. Recorded-ciphertext decryption (HNDL) is **forward secrecy's** job, which (a) provides. Residual PCS-favouring cases — transient memory disclosure, live-VM-snapshot, side-channel extraction, bad handshake-time entropy — are real but narrow and each has a better-targeted answer (the Rust rewrite; co-residency avoidance; startup entropy health checks) than a periodic full re-handshake. **Options rejected, with reasons:** **(b) WireGuard-style periodic re-handshake.** *Figures corrected 2026-09-01 from a primary-source read of Donenfeld's paper (the debt this row flagged as "not re-verified at primary source" is now discharged; corpus copy at `shekyl-dev` `4cabe8ef2`):* WireGuard's handshake is **148 B initiation + 92 B response = 240 B** (§5.4.2/§5.4.3 field layouts), so against BOLT-8's classical 166 B the ratio is **≈1.45×, not ~15×** — the earlier figure compared a *hybrid* re-handshake against a *classical* BOLT-8 number. WireGuard is `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (**IKpsk2**, not plain `IK`; immaterial to PW-19a, which turns on the `K` pre-message present in both). And WireGuard **already jitters** its rekey expiry (§6.1, *"an additional amount of jitter is added to the expiration"*) — for thundering-herd prevention, so the accurate objection is that the jitter is **not sized for fingerprint suppression**, not that jitter is absent. **The ruling is unaffected: it never rested on the ratio** ("on the merits rather than on cost"), which is exactly why a decorative figure had to be corrected before it was quoted into a normative spec. **The real argument against (b) is a privacy one, added 2026-09-01:** option (a) costs **zero bytes on the wire** — both sides derive `ck', k'` from state they already hold — so the classifiable handshake flight is paid **once per connection and never again**. Option (b) would **re-emit that flight on a schedule**: a repeated DPI opportunity *and* a cadence signal, i.e. PW-28's hazard arriving by a second route. Option (a) reduces the handshake's observable footprint to the theoretical minimum, exactly one event per connection. That is stronger and cleaner ground than the cost comparison. *Consequence worth carrying:* handshake exposure is therefore a function of **connection lifetime**, which ties this row to PW-23 — stable work-based tenure amortises the flight toward the number of distinct peers a node maintains rather than scaling with time. **(c) KEM-ified ratchet** — PW-4 bites (Double Ratchet's asymmetric half is DH-shaped); research-grade, rejected per get-it-right-not-get-it-now. **Structural finding worth keeping:** the three options are **not independently tunable** — a symmetric KDF chain has no entropy source an attacker lacks, so "harden (a) for healing" does not converge on a modified (a); it *becomes* (b) or (c). If PCS is ever required, (a) is disqualified at the start, not after a hardening attempt. **Pattern-transferability, stated explicitly because this is exactly the kind of thing that gets missed unless specified.** BOLT-8 is `Noise_XK` and WireGuard is `Noise_IKpsk2` — both static-key patterns, both requiring node ids, both **incompatible with the no-node-id posture (PW-19a). Shekyl is not using either pattern.** What transfers is the *rotation mechanism*, and it transfers because it is **framework-level, not pattern-level**: every Noise handshake in every pattern maintains a chaining key `ck`, mixed with each key-agreement result and split into directional cipher keys at the end. `XK` accumulates three DH results into `ck` (two involving statics); `NN` accumulates exactly one (`ee`), plus the ML-KEM shared secret in the hybrid variant. Fewer inputs, no statics — **but `ck` exists either way**, and `ck', k' = HKDF(ck, k)` reads only `ck` and `k`, with no dependency on how `ck` was derived. It applies to `NN` verbatim. **What does NOT transfer is the security context:** BOLT-8 rotates on an authenticated channel, Shekyl would rotate on an unauthenticated one. That does not erode the property this row selects rotation for — forward secrecy against recorded ciphertext is a property about the **path observer**, who was never a participant and gains nothing from the absence of authentication (see §1's threat model). What rotation cannot do on an unauthenticated channel is protect you from your counterparty — already conceded under PW-19a, and no rekey scheme in any pattern would have helped there. **Do not read "we adopted BOLT-8's rekey" as "we adopted BOLT-8's pattern"** — the two halves have different transferability, which is why the correction that BOLT-8 *is* Noise-plus-rotation (above) is load-bearing rather than pedantic. **Scope of this ruling: gossip/P2P only.** RPC has operator-controlled endpoints, no open join, genuinely sensitive plaintext, and session-key theft as the only path in — a different threat model that may warrant a different answer, and is governed by `RPC_TRANSPORT_POSTURE.md`, not here. | `lightning/bolts/08-transport.md` (master, read this session — rotation §, act sizes, encrypted length prefix); WireGuard rekey timers **re-verified at primary source 2026-09-01** (Donenfeld, `wireguard.pdf` §6.1: Rekey-After-Time 120 s, Reject-After-Time 180 s, Rekey-Attempt-Time 90 s, Rekey-Timeout 5 s, Keepalive-Timeout 10 s, Rekey-After-Messages 2⁶⁰, Reject-After-Messages 2⁶⁴−2¹³−1; handshake sizes §5.4.2/§5.4.3); this session's threat wargame | **Ruled (gossip). Open only for RPC, out of scope here.** |

---

## 2. Levin-inherited wire findings (Survey A's L-items + this session's addition)

| ID | Finding | Evidence | Status |
| --- | --- | --- | --- |
| PW-9 (L-1) | `LEVIN_SIGNATURE` is a fixed 8-byte constant at **offset 0** of every connection (`header.rs:136`, `:181`) — **one 8-byte comparison, needing no decryption and no connection state**, answers "a handshake for *what*". **Survives PW-3's retirement, independently and on its own merits: removing it is cheap and unambiguous.** **But it must not carry an anonymity claim.** It raises the cost of *bulk passive scanning* — sweeping traffic for a known prefix — and does **nothing** against *targeted active probing* (PW-3a), which is the attack that actually determines whether an IP runs Shekyl. State what it buys. | `rust/shekyl-levin/src/header.rs:14`, verified this session | Open — hard requirement, scoped to passive-scan cost |
| PW-10 (L-2) | `DEFAULT_MAX_PACKET_SIZE = 100 MB`, inherited not derived. | `header.rs:27` | Open — derive from largest legitimate message |
| PW-11 (L-3) | Unknown flag bits preserved verbatim — a covert channel between colluding peers across an honest relay, for a protocol with one implementation. | `header.rs:29-30` | Open — reject unknown bits pre-genesis |
| PW-12 (L-4) | `return_code: i32` on every bucket — inherited RPC-over-Levin affordance leaking implementation state. | `header.rs:103` | Open |
| PW-13 (L-5) | Compression before encryption is a CRIME/BREACH-class oracle; interacts directly with Dandelion++'s padding/size defenses. | `compress.rs:25,32` | Open — check compression is disabled wherever padding is load-bearing |
| PW-14 (L-6) | Persistent `peer_id`, `rpc_port` in the handshake link a node across IP changes; `rpc_port` directly contradicts RT-9's `--public-node` removal. | `p2p_protocol_defs.h:180-196` | Open — see §3 below, largely superseded by the identity-model direction |
| PW-15 (L-7, new this session) | No rate limit on Ping/Timed-Sync/handshake messages; enables both cheap connection churn and a watermarking side channel (message-rate modulation). | `2509.10214v1_Levi_p2p.pdf` (handshake flooding, throttled Timed Sync measurements); `2607.07062v1_TOR_Deanonymizing.pdf` (ProxyMark's rate-based watermark method) | Open |
| PW-16 | Full 250-peer list disclosed on every handshake response and Timed Sync — topology-mapping aid for planning eclipse/Sybil attempts. | `2509.10214v1_Levi_p2p.pdf` §2.1 | Open |
| PW-27 (L-6, formerly Survey A U-6) | `NOTIFY_NEW_BLOCK` still lives alongside `NOTIFY_NEW_FLUFFY_BLOCK` — two block-propagation paths that must agree on validation, on a chain with no fluffy-block transition to justify the legacy one, and a path the Dandelion++ zone analysis may not have covered. Re-confirmed on `dev` @ `ab3cc98e6`: both structs present. | `cryptonote_protocol_defs.h:184` (`NOTIFY_NEW_BLOCK`), `:334` (`NOTIFY_NEW_FLUFFY_BLOCK`) | Open |
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
proposal), not a deviation from the framework. It cleanly kills PW-14/L-6.
Costs: identity-based banning dies (a banned peer reconnects with a fresh
key) — **see PW-20**, the required replacement.

**PW-19a — NO AUTHENTICATION BETWEEN UNKNOWN PEERS. Standing design
constraint, ruled multiple times, not a gap and not reopenable here.**
The moment a durable peer identity exists, it becomes an enumeration key:
interactions cluster against it, the cluster is enumerated, and the privacy
property is gone. `NN` is therefore not a compromise forced by a lack of
options — it is the pattern that *matches the requirement*. This constraint
is the same one that already killed persona-identity-as-admission-signal
(PW-21) and address/subnet/ASN-based admission (§6.10,
`DAEMON_RELAY_PRIVACY.md`); it has now been re-litigated at least three
times and must not be re-opened by a future round noticing that `NN` is
unauthenticated. Its landed citation is below.

**Why `XK`/`IK` are inapplicable, not rejected — pre-empting the predictable
"but Lightning/WireGuard authenticate, why don't we" re-litigation.** Noise
pattern names are two letters: initiator's static handling, then
responder's. **N** = no static key; **K** = static **Known to the other
party in advance**, supplied out-of-band as a *pre-message* and never sent
on the wire; **X** = static transmitted (encrypted) during the handshake;
**I** = static sent immediately. So the `K` in `XK` is not a mechanism that
authenticates strangers — **it is the assumption that the parties are not
strangers.** BOLT-8 states it directly: as a pre-message the initiator must
know the responder's identity public key, which is never transmitted during
the handshake; a failed act-one MAC means precisely that the initiator did
not know it. WireGuard's `IK` is the same on the responder side — the paper
has peers exchanging static public keys with each other a priori as their
static identities, OpenSSH-style. In both, the prior knowledge comes from
out-of-band configuration: a `nodeid@host:port` connection string, or a
config file. **Authentication is by definition "this is the key I already
expected," so it requires a trust anchor established outside the protocol.**
A gossip peer found via discovery has none by construction. `XK`/`IK`
therefore have a precondition Shekyl's posture forbids — they are not
options declined on privacy grounds but patterns whose entry requirement
does not exist here. `NN` is not the weak choice among available patterns;
it is the only honest one, and its properties (both parties ephemeral, no
static anywhere, nothing to enumerate) are what PW-19a *requires*, not a
cost it imposes.

**Citation — task closed.** No single landed sentence states this
constraint; **three independent rulings jointly entail it**, which is
stronger than one sentence and is how the row should be cited:
1. **Scope level** — `RPC_TRANSPORT_POSTURE.md` §2.1 (`:99-106`): "The
   peer-to-peer layer talks to strangers by construction; that is what a
   blockchain is… RPC is operator-to-operator; P2P is adversarial by
   design and hardened separately."
2. **Mechanism level** — `DAEMON_RELAY_PRIVACY.md` §12.10 (`:2480`,
   `:2498`): admission is "transport-blind (work, not identity)" — the
   selection rule deliberately does not distinguish adversary from honest;
   `:7396` confirms the toll is paid in work precisely so a fresh peer
   needs no cross-session identity.
3. **Anti-ruling level** — `Q12_D6A_PEER_DISCOVERY_RUN.md` (`:2910-2917`):
   a stable identity announced at the p2p layer "would hand back the
   linkage the transport layer is built to deny," with identity-as-signal
   rejected twice (`:2979`, `:3013` — "a privacy regression wearing a…"
   sybil-resistance and robustness argument respectively).

Cite all three, with the note that the constraint is **entailed jointly** —
scope (strangers by construction), mechanism (admission is work-not-identity),
anti-ruling (stable identity is the hazard the transport denies) — rather
than stated in any single sentence. That phrasing also inoculates against
the "but no doc actually says it" form of re-litigation this row exists to
prevent.

**The reusable check, added 2026-09-01 after this constraint disposed of a
fourth mechanism.** PW-19a has now killed persona-identity-as-admission-signal
(PW-21), address/subnet/ASN admission (`DAEMON_RELAY_PRIVACY.md` §6.10),
identity-as-signal twice in `Q12_D6A_PEER_DISCOVERY_RUN.md`, and — via PW-3a —
handshake obfuscation. The pattern is consistent enough to state as a test:

> **Any mechanism that would let a node distinguish a legitimate peer from a
> prober requires prior knowledge of that peer, and prior knowledge is
> forbidden by PW-19a.**

Check a proposed mechanism against that sentence **before** costing it. It
disposes of probe-resistant transports, admission whitelists and handshake
obfuscation without re-deriving the argument from whatever figure prompted the
proposal — which is how PW-3's padding requirement survived as long as it did.

**Consequences, recorded rather than treated as open problems:**
- **Clearnet MITM is a conceded adversary capability.** Not a gap. On Tor
  the question is moot — an onion address *is* a public key, so the
  endpoint is self-authenticating.
- **Every node is a technical man-in-the-middle by construction** — that is
  what relaying is. There is no privileged interposer position to steal.
- **What still holds without authentication:** *validity* is guaranteed by
  consensus (no peer can make you accept an invalid block or tx);
  *propagation privacy* by D++ and the relay-privacy work; *liveness* by
  the eviction floor (PW-23). What is **conceded** is the observation
  adversary — a node that relays correctly and records arrival metadata —
  ruled out of scope in §12.10 and taxed rather than prevented.

**PW-23a — tenure is a continuously re-earned observation, never a cached
credential** (implementation constraint on PW-23, follows directly from
PW-19a). Work-based selection must remain a record of *observed relay work
on this connection*, evaluated continuously. It must never become standing
granted to whoever occupies an endpoint. Under PW-19a an interposer can
take over a guard slot; the design survives that precisely because tenure
never trusted the endpoint, only the work — an interposer inherits nothing
but the obligation to keep relaying honestly, and the eviction floor fires
the moment it stops. **The failure mode to guard against is an
implementation that caches a tenure score against an endpoint and skips
re-evaluation** — a rule-47-shaped hazard (a gate whose subject has
decayed still reads green). Falsifiable at implementation review: name the
edit that makes the re-evaluation stop, and show a check that fails on it.

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

**Partial answer already in the tree, verified this session — narrows the
question further.** `shekyl-p-transport::derive_socks_user`
(`rust/shekyl-p-transport/src/lib.rs:134`) derives a per-persona SOCKS
username by cSHAKE256 over the **full** canonical `P` id (no truncation or
modulo, collision-resistant except with negligible probability), giving
per-persona SOCKS stream isolation so personas do not share a circuit fate;
`Q12_D6A_PEER_DISCOVERY_RUN.md` §10.9 pins one-P-per-wallet-on-wire. So the
P-transport lane **already denies persona linkage at the transport layer**
for the paths it covers. PW-22 is therefore not "is persona linkage
defended" — it is strictly a **coverage gap check**: does that isolation
extend to the serve-credit *submission* path, or only to the serving path?

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

**Citation corrected 2026-09-01 — the claim survives, its pointers do not.**
Two errors, both found by reading `DAEMON_RELAY_PRIVACY.md` at the pin rather
than trusting this register's own references:

- **`ρ` is not mentioned in §12.10 at all.** Its canonical statement is
  **§13.5** (*"`ρ` is underspecified, not undecided-pending-judgment"*), with
  supporting statements at the doc's status header, §7's Q-10 bullet and
  §12.6's blocked-state note. A round that read §12.10 looking for `ρ` would
  find the admission mechanism and conclude the register had mis-described it.
- **§12.11's body is superseded in part** by two banners it carries: the
  **Exploit tier is deleted** as D++ §4.5 version-checking, and the live
  mechanism reduces to a **uniform random draw over the non-cooled admissible
  set** (that document's §§52/53/54). The body below those banners reads as
  current spec and is not. **Whoever specifies `ρ`/`g_max` must read the
  superseding sections, not §12.11's body** — building against the deleted
  tier would implement a mechanism the relay lane already withdrew.

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
