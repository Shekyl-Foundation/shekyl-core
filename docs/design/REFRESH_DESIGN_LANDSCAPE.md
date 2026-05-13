# Refresh design landscape — V3.0 substrate

**Status.** Substrate doc (2026-05-12). Lands as the design-space
reference Round 1 of [Stage 1 PR 4 (`RefreshEngine`
extraction)](./STAGE_1_PR_4_REFRESH_ENGINE.md) evaluated the
producer-redesign question (§5 of that doc) against. This document
is reference material; design dispositions live in their respective
PR design docs and reference this landscape rather than restating
it.

The doc is *substrate*, not *spec*: it does not bind any wallet
behaviour; it surveys the design space and records the negative
results that scope the producer-redesign axis Round 1 settled (α —
preserved current shape, per
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
§5.4). The negative results are forward-looking: they describe
which axes V3.0 is choosing not to take and why, not assertions
that the alternatives are wrong forever.

**Scope.** This doc covers wallet-side refresh — the pipeline by
which a wallet identifies on-chain outputs addressed to it. The
post-genesis chain is canonical
`RCTTypeFcmpPlusPlusPqc`-only ([`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc));
no pre-genesis chain or legacy transaction types factor into the
landscape.

---

## §1 Purpose

PR 4 Round 1 chose between three producer-pattern strategies (α
preserved current shape, β internal batching, γ consumer-driven
streaming). The choice is meaningful only when evaluated against
the broader refresh-design landscape — what other axes *could*
PR 4 redesign, and which axes are out-of-scope by precondition?
This document records the precondition-bounded design space so
PR 4's α-disposition is evaluable against the whole landscape,
not against ad-hoc adjacency.

The doc is also the named home for refresh-adjacent items that
do not fit any single per-trait PR's scope: FMD and OMR research
directions, the view-tag property already operational from PR 3,
and the pruning-vocabulary disambiguation needed to read the V3.0
bandwidth FOLLOWUP entry correctly. Per
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)'s
"deferred without a named home is the failure mode" framing, the
items below have a home here even when their resolution is
deferred indefinitely.

---

## §2 Privacy-by-default precondition

[`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) priority 2
binds: privacy is the product; every user gets the same anonymity
guarantees by default. Refresh design respects this by
construction — the wallet's anonymity property is "an observer
cannot link an on-chain output to the wallet that received it
without the wallet's secret material," and refresh's role in
preserving that property is to perform the
output-detection-and-decoding work locally, on the wallet's host,
without revealing the receiving subaddress index or the set of
candidate ciphertexts to any external party.

This precondition has direct consequences for the design
landscape:

- **Scan-on-client is the default.** The wallet processes blocks
  itself, applying the view-tag pre-filter and the full hybrid
  decap path, and observes only its own outputs. No external
  party learns which outputs were received.
- **Designs that move scanning off-client must preserve the same
  anonymity guarantees.** Server-assisted scan, cloud refresh,
  and any "cheaper" off-client design must demonstrate that the
  guarantee under "every user runs scan-on-client" is preserved
  exactly under the alternative — not in an
  asymptotic-or-statistical sense but in a per-output sense
  matching the on-client design.
- **The privacy property does not soften under
  performance pressure.** A refresh design that is "fast on
  resource-constrained hardware but reveals the subaddress
  index to the daemon at probability `p`" violates the
  precondition regardless of how small `p` is. Privacy is not
  a setting and is not amortized.

The producer-redesign axis (α/β/γ) operates *within* the
scan-on-client default: all three strategies do scan-on-client;
they differ only in how the producer communicates results to
consumers within the wallet's address space. None of α/β/γ
weakens the privacy precondition. The negative-result sections
below (§4 FMD, §5 OMR) cover designs that *do* operate
off-client and explain why they fall outside V3.0's design
space.

---

## §3 The view-tag pre-filter (operational today)

The view-tag pre-filter is the wallet's first-line scan-on-client
optimization, operational as of Stage 1 PR 3 / M3a–M3b. The
mechanism is documented in
[`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md)
§3.1.1 ("Scanner two-step pattern is implementation orchestration
hidden behind the workflow boundary"). Restated here for the
landscape:

- **Step 1 — X25519 view-tag pre-filter.** Classical X25519 ECDH
  against the X25519 ephemeral component of the on-chain output's
  `HybridCiphertext`. Produces a 32-byte raw shared secret used
  as input to view-tag derivation. The view-tag is a 1-byte
  derived value (`VIEW_TAG_BYTES = 1` per
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md)
  §3 amendment A4); a mismatch rejects the output without doing
  the expensive PQC half. ~1/256 of unrelated outputs collide on
  the view-tag, but ~255/256 are rejected by a single classical
  ECDH.
- **Step 2 — Full hybrid decap.** Only outputs that pass the
  step-1 view-tag check enter the full hybrid KEM decap against
  the entire `HybridCiphertext`. Full decap produces a 64-byte
  hybrid shared secret that feeds the HKDF chain deriving
  output-secret material.

The split is implementation orchestration hidden behind PR 3's
workflow-shape `try_claim_output` boundary — PR 4 does not
re-litigate it; PR 4's α-disposition inherits the two-step
pattern unchanged. The performance property (~1/256 of outputs
proceed past the cheap classical step) is the load-bearing reason
scan-on-client is tractable on commodity hardware in V3.0.

The view-tag is recipient-only-derivable: the X25519 ephemeral
key the sender publishes and the recipient's view secret are
both required to derive the view-tag, so a third-party observer
who sees only the on-chain output cannot derive it. The view-tag
is therefore *not* a privacy-degrading hint — its presence on
chain reveals nothing about which wallet the output is addressed
to, only that the sender derived it correctly.

---

## §4 FMD (fuzzy message detection) — negative result for V3.0

FMD ([Beck, Len, Miers, Green, IACR ePrint 2021/089](https://eprint.iacr.org/2021/089))
proposes a primitive that lets a recipient publish a "detection
key" allowing a third-party server to identify candidate
incoming outputs while learning only that each output is "either
yours or not yours, with false-positive rate `p`." The recipient
runs the expensive decryption only on the candidate set the
server returns.

**The structural tension with V3.0's privacy precondition.**
FMD's privacy property is parameterized by `p`: lower `p` means
fewer false positives (smaller candidate set; cheaper recipient
work) but more linkability across multiple detection events;
higher `p` means more false positives (larger candidate set;
more recipient work) but less linkability. The setting question
is which `p` value V3.0 would adopt:

- **`p` low enough to preserve subaddress unlinkability.** The
  candidate set the server returns becomes a near-exact match
  for the recipient's true-positive set; an observer comparing
  two detection events from the same recipient learns "these
  two events share a small candidate set" with high probability,
  which is the linkability degradation the privacy precondition
  rejects. As `p → 0`, FMD collapses to "the server learns the
  recipient's subset" — the scan-on-server property the
  precondition forbids.
- **`p` high enough to reduce client scan cost.** At any `p`
  large enough to produce meaningful client-side savings (say
  `p ≥ 1/64`), the false-positive rate dominates the recipient's
  cost — the recipient still does ~1/64 of the scan work, which
  is comparable to the view-tag pre-filter's existing ~1/256
  classical-rejection cost (§3 above). At that point FMD's
  cost win evaporates while the privacy weakening accumulates
  across detection events.

In short: there is no `p` setting that produces a V3.0-acceptable
balance between client-side cost reduction and the privacy
property the precondition requires. The view-tag pre-filter
(§3) already delivers the cheap-rejection property without the
linkability axis FMD introduces, and does so on-client.

**Forward direction.** FMD is a research direction whose
re-evaluation belongs in the V4 lattice-only era, where the
PQC cryptographic primitives FMD's literature has explored
(lattice-based detection keys with redaction-resistance) align
with Shekyl's V4 transition. A V4 reconsideration of FMD against
the V4 threat model is the natural re-evaluation point. FMD is
*not* a V3.x deferral — V3.x is the V3.0-platform window in
which the V3.0 privacy precondition still binds.

**Target.** V4 research direction (re-evaluation gated on V4
lattice-only transition).

---

## §5 OMR (oblivious message retrieval) — negative result for V3.0

OMR ([Liu, Tromer, USENIX Security 2022](https://eprint.iacr.org/2021/1256))
proposes a primitive that lets a server perform homomorphic
output detection over the encrypted stream and return a
recipient-decryptable candidate list, ideally without learning
which outputs are the recipient's. The server-side work is
expensive (FHE / SHE operations); the recipient work is small
(decrypting the candidate list).

**The structural tension with V3.0's privacy precondition.**
OMR's privacy property depends on the FHE/SHE construction's
side-channel resistance plus the network-layer property that the
server cannot correlate the recipient's request pattern with the
candidate-list contents. Each layer is an attack surface:

- **FHE/SHE construction.** Practical OMR constructions rely on
  somewhat-homomorphic schemes whose performance trades against
  privacy. Performance-tuned parameter sets are not always
  audited as carefully against the privacy property as they are
  against the correctness property. The *V3.0* threat model
  ([`30-cryptography.mdc`](../../.cursor/rules/30-cryptography.mdc))
  treats memory disclosure and side-channel observability as
  primary; folding an FHE/SHE construction into the wallet's
  threat surface adds discipline review across primitives the
  rest of the wallet does not use.
- **Network-layer correlation.** Even if the FHE construction is
  perfect, traffic-analysis attacks against the recipient's
  request pattern (request size, timing, frequency) re-derive
  partial scan-set membership. Defending against
  traffic-analysis at the network layer is a separate
  discipline (Tor-grade onion routing, Loopix-style mix nets,
  etc.) that V3.0 does not bind into the refresh layer; OMR
  would import that discipline as a precondition the wallet
  could not enforce locally.
- **Server collusion.** The "server cannot learn which outputs
  are yours" property assumes the server is honest-but-curious
  with no side-channel. In a deployment where multiple wallets
  share an OMR server, server compromise (or server-operator
  malice) collapses every client's privacy at once — a
  failure mode that scan-on-client does not have because each
  client's scan is independent.

OMR is not impossible to deploy correctly, but the discipline
budget required to verify the FHE/SHE primitive, the
traffic-analysis defense, and the server-collusion model lands
several disciplines beyond V3.0's scope. The view-tag + scan-on-client
combination (§3) delivers the V3.0 precondition without
introducing those disciplines.

**Forward direction.** OMR is a V3.x research direction
re-evaluable when (a) FHE/SHE primitives mature into
auditable-against-privacy-property shapes, (b) traffic-analysis
defense is a separate stable subsystem the wallet can compose
against, and (c) server-collusion mitigations exist that
preserve per-client privacy independence. Each precondition is
its own multi-quarter scope; OMR is correctly out of V3.0.

**Target.** V3.x research direction (re-evaluation gated on the
three preconditions above).

---

## §6 The remaining axis — producer pattern (α/β/γ)

With the view-tag pre-filter operational (§3) and the FMD/OMR
off-client axes scoped out (§4, §5), the remaining refresh
design axis V3.0 chooses on is the **producer pattern** — how
the on-client refresh producer communicates scan results to
consumers within the wallet's address space.

PR 4 Round 1 settled this axis:
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
§5.4 dispositions α (preserved current shape). The four-criteria
rationale (PR 4 extraction cleanliness; PR 5 two-phase
build/submit/discard contract; reservation-tracker reorg
surfacing; Stage 4 actor compatibility) is recorded there;
this landscape doc is the substrate the rationale evaluates
against rather than a re-statement of the rationale.

**Cross-axis interaction.** α inherits the scan-on-client
bandwidth cost: each block is fetched serially over a daemon
RPC round-trip (per
[`engine/refresh.rs`](../../rust/shekyl-engine-core/src/engine/refresh.rs)).
The bandwidth FOLLOWUP entry in
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) (V3.0, "Refresh
bandwidth tradeoff under α") names this cost as the cost-benefit
artifact PR 4's Round 1 disposition consumed. Whether the V3.0
RC-stabilization profile justifies a follow-up β-shape PR is the
R2 residual question (per
[`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
§5.4.3).

---

## §7 Sidebar — pruning vocabulary

The bandwidth FOLLOWUP entry and the §6 cost-benefit framing
both rely on the word "prune," which means materially different
things in different parts of the stack. β-style internal
batching, prune-by-birthday, and prune-by-skip-to-height are all
"refresh less data" but operate on different axes. This sidebar
disambiguates so subsequent work-list entries can name *which*
prune they refer to.

| Prune name | Where it lives | What it discards |
| --- | --- | --- |
| **Daemon-side `--prune-blockchain`** | full node | historical witness/proof data; keeps consensus state. Wallet refresh against pruned daemons works for current blocks; cold-sync requires `--no-prune` source for the wallet's birthday-to-tip range |
| **Archival prune (`--no-prune` policy)** | Foundation reference daemons | nothing; the archival role exists precisely so cold-sync clients have a `--no-prune` source to scan against (per [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) multi-source disposition) |
| **RPC-server prune** | wallet-RPC server (the `wallet_rpc_server` cutover scope) | mempool / cache / response-buffer data; affects long-running RPC sessions, not on-chain validity |
| **Wallet-side prune-by-birthday** | wallet client | blocks below `refresh_from_block_height`; the producer skips the prefix entirely when starting a refresh. P2 FOLLOWUPS entry on `dev` ("P2: wallet-birthday plumbing not wired into producer start-height") names this as a deferred V3.0 item |
| **Wallet-side prune-by-skip-to-height** | wallet client | blocks below a user-pinned `skip_to_height`; ad-hoc prune the user invokes after restoring from seed when they know the receive period started at a specific height. Future PR 4 plumbing |

**Why this matters here.** β/γ analysis often conflates "scan
less data" with "scan less network bandwidth." They are
independent axes:

- **Scan less data.** β internal batching does not change the
  set of blocks fetched; it changes the fetch *concurrency*.
  Prune-by-birthday and prune-by-skip-to-height *do* change the
  set of blocks fetched (the prefix is dropped entirely).
  Daemon-side `--prune-blockchain` does *not* change the set of
  blocks fetched (the wallet still asks the daemon for every
  block in its range; pruning affects what data the daemon
  serves per block, not the block count).
- **Scan less network bandwidth.** β internal batching reduces
  *latency* but not *bytes*. Prune-by-birthday reduces both
  bytes and latency for cold-sync. Daemon-side
  `--prune-blockchain` reduces bytes per block but does not
  reduce the round-trip count.

Under α, each block is fetched in one daemon RPC round-trip
(serial). The bandwidth FOLLOWUP entry names which prune-shape
is the intended remediation: prune-by-birthday for the cold-sync
prefix (where birthday plumbing already exists at the prefs
layer per the P2 FOLLOWUP), β-style internal batching for the
post-birthday range (which prune-by-birthday cannot reduce
further without losing on-chain coverage). Round 2 R2 dispositon
revisits whether β's deferral is the long-term answer or whether
a different prune-shape refinement is preferable.

---

## §8 Cross-references

- **PR 4 Round 1 disposition.**
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4 (α — preserved current shape).
- **PR 4 work-list table.**
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.5 (where each refresh-adjacent item lives).
- **Bandwidth FOLLOWUP entry.**
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) V3.0 ("Refresh bandwidth
  tradeoff under α").
- **View-tag pre-filter mechanism.**
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./STAGE_1_PR_3_KEY_ENGINE.md)
  §3.1.1 (scanner two-step pattern).
- **`RefreshEngine` trait surface (binding).**
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 (Round 2 producer/driver collapse) and §7
  (four-checkpoint cancellation discipline).
- **Validation-surface guard.**
  [`19-validation-surface-discipline.mdc`](../../.cursor/rules/19-validation-surface-discipline.mdc)
  (named on `dev` 2026-05-10; cites PR 4 Round 1 as
  forward-looking worked example for FMD / OMR / bandwidth /
  birthday / async-skip surface separation).
- **Privacy precondition.**
  [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) priority 2
  (privacy as the product) and the V4 transition framing in
  [`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc).
- **No Monero legacy.**
  [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc)
  (canonical chain is `RCTTypeFcmpPlusPlusPqc` from genesis;
  no pre-genesis refresh paths factor into the landscape).
