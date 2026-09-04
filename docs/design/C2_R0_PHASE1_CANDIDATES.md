# C2-R0 Phase 1 — Candidate Absent Consensus Rules

**Status:** CLOSED as record — the C2-R0 phase-1 corpus study, produced
2026-09-02/03 outside the tree and landed verbatim (plus this banner and one
phase-2 editorial marker at the Qubic profitability figures) by
phase 2 so that the §12 GAP register's provenance citations resolve for a
tree reader. Phase 2's dispositions of every candidate live in
[`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §12; corrections
land THERE, never here — this document is the frozen input. Appendix C
was written by phase-2 routing (steering + this session) before landing.

**Method:** negative space. Derived from the deployed-chain incident record and the
academic literature, **without reading the Shekyl tree or its design docs.** No
`file:line` anchors appear below, deliberately. Every candidate is a hypothesis for
phase 2 to ground; several will turn out to be present already, and *that is the
expected failure mode of this instrument* — the opposite failure (a rule that ought
to exist, has no code site, and is therefore invisible) is the one this round exists
to correct.

---

## 0. Methodology and the completion claim

### 0.1 The completion claim is source-based, not exhaustive

There is no mechanical enumeration of "rules that should exist." Any total I wrote
would be unfalsifiable. So the claim made here is exactly this and nothing more:

> **The sources listed in §0.2 were read, and they produced the 13 candidates in
> §1–§13.** A reviewer can falsify this by naming a source I did not read and a
> candidate it would have produced.

I do **not** claim these are all the absent rules. I claim these are the ones this
corpus yields.

### 0.2 Corpus actually read (with what each yielded)

| # | Source | URL | Yielded |
|---|---|---|---|
| S1 | ECIP-1100 (MESS) full text | https://ecips.ethereumclassic.org/ECIPs/ecip-1100 | C1 (mechanism + the 31× cap + the self-declared bifurcation risk) |
| S2 | ECIP-1110 "Deactivate MESS" + ETC discussion #522 | https://ecips.ethereumclassic.org/ECIPs/ecip-1110 · https://github.com/orgs/ethereumclassic/discussions/522 | C1 (the **sunset clause** finding — the retrofit was switched off in Jan 2024) |
| S3 | VeriBlock MESS vulnerability disclosure (Jul 2021) | https://veriblock.org/veriblock-foundation-discloses-mess-vulnerability-in-ethereum-classic-blockchain/ | C1 trade (permanent-partition exploit, ~$10K–$50K cost) |
| S4 | BitMEX Research, "Bitcoin Cash ABC's rolling 10 block checkpoints" (Nov 2018) | https://www.bitmex.com/blog/bitcoin-cash-abcs-rolling-10-block-checkpoints | C1 trade (deliberate-split vector; the offline/resync node problem) |
| S5 | Horizen delayed-block-submission penalty (Oct 2018) | https://blog.horizen.io/horizens-51-attack-solution/ | C2 (the shipped delay-penalty retrofit) |
| S6 | tevador, "Publish or Perish" — monero-project/research-lab#144 | https://github.com/monero-project/research-lab/issues/144 | **C2 (primary)** — full late-block + uncle + reward-splitting spec |
| S7 | Zhang & Preneel, *Publish or Perish* (CT-RSA 2017) | https://www.esat.kuleuven.be/cosic/publications/article-2746.pdf | C2 academic root |
| S8 | "Inside Qubic's Selfish Mining Campaign on Monero" (arXiv 2512.01437) | https://arxiv.org/html/2512.01437 | C2 + C13 (measured 23.38% avg / 28.33% during withholding; ten withholding periods) |
| S9 | zawy12/difficulty-algorithms **issue #30 — Timestamp Attacks** | https://github.com/zawy12/difficulty-algorithms/issues/30 | **C3, C5 (primary)** — twelve attack vectors, the four requirements, CryptoNote-default critique |
| S10 | zawy12/difficulty-algorithms **issue #13 — Handling Bad Timestamps** | https://github.com/zawy12/difficulty-algorithms/issues/13 | C3 (FTL=7200 quantified; solvetime clamping; the Graft case) |
| S11 | Verge 2018 timestamp attacks (Apr + May) | https://www.coindesk.com/markets/2018/06/05/verges-blockchain-attacks-are-worth-a-sober-second-look · https://www.apriorit.com/dev-blog/563-verge-mining-hack | C3 evidence |
| S12 | BIP113 (median-time-past as locktime endpoint) | https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki | **C4 (primary)** |
| S13 | Great Consensus Cleanup revival thread (bitcoindev, 2024) | https://groups.google.com/g/bitcoindev/c/CAfm7D5ppjo | C3, C11, C12 |
| S14 | BIP94 / testnet4 timewarp fix; bitcoin/bitcoin#30647, #29775, #31376 | https://github.com/bitcoin/bitcoin/pull/30647 | C3 (2024–25 evidence that chains still ship timestamp rules) |
| S15 | Dash **ChainLocks** DIP-0008 | https://github.com/dashpay/dips/blob/master/dip-0008.md · https://medium.com/dash-org/mitigating-51-attacks-with-llmq-based-chainlocks-7266aa648ec9 | **C6 (primary)** |
| S16 | monero-project/monero **#10064 — Temporary rolling DNS checkpoints** | https://github.com/monero-project/monero/issues/10064 | C1 + C6 (what Monero considered post-Qubic and why it stalled) |
| S17 | Bitcoin Core `assumevalid` / `nMinimumChainWork` (PR #9484, #9779; release 0.14.0) | https://bitcoincore.org/en/releases/0.14.0/ · https://github.com/bitcoin/bitcoin/pull/9779 | **C7 (primary)** — and the checkpoint distinction |
| S18 | **CVE-2019-25220** headers-spam memory DoS + anti-DoS headers sync PR #25717 | https://bitcoincore.org/en/2024/09/18/disclose-headers-oom/ · https://github.com/bitcoin/bitcoin/pull/25717 | C7 (attack cost fell to 0.14 BTC by Sep 2024) |
| S19 | Lovejoy / MIT DCI — Bitcoin Gold reorgs & counterattacks | https://medium.com/mit-media-lab-digital-currency-initiative/reorgs-on-bitcoin-gold-counterattacks-in-the-wild-da7e2b797c21 · https://www.dci.mit.edu/projects/51-percent-attacks | C1 evidence, C8 (Binance moved 12 → 20 confirmations) |
| S20 | Vertcoin 51% attacks (Dec 2018, Dec 2019) | https://www.coindesk.com/tech/2019/12/02/the-vertcoin-cryptocurrency-just-got-51-attacked-again · https://medium.com/coinmonks/vertcoin-vtc-is-currently-being-51-attacked-53ab633c08a4 | C1 evidence (307- and 603-block reorgs) |
| S21 | ETC Aug 2020 reorg reports (3,693 / ~4,000 / >7,000 blocks), plus the later attributions | https://www.coindesk.com/markets/2020/08/01/ethereum-classic-suffers-reorganization-that-resembles-51-attack-amid-miner-complications · https://www.coindesk.com/markets/2020/08/29/ethereum-classic-hit-by-third-51-attack-in-a-month · https://www.okx.com/academy/en/okex-responds-to-ethereum-classic-51-attacks-reveals-its-hot-wallet-system-incident-report · https://www.coinbase.com/blog/coinbases-perspective-on-the-recent-ethereum-classic-etc-double-spend | C1 evidence **and** the misattribution finding (App. B.3): the same event was first reported as an offline miner and later confirmed as a deliberate shadow-chain attack |
| S22 | Monero dynamic block weight / "blockchain big bang" research | https://github.com/noncesense-research-lab/Blockchain_big_bang · https://monero-book.cuprate.org/consensus_rules/blocks/weights.html | C11 (and a likely-already-present note) |
| S23 | Monero hard-fork voting (`hardfork.h`, Monero Book) | https://monero-book.cuprate.org/consensus_rules/hardforks.html | **C9 (primary)** |
| S24 | Zcash slow-start mining (zcash#762; ECC blog) | https://github.com/zcash/zcash/issues/762 · https://blog.z.cash/slow-start-and-mining-ecosystem/ | **C10 (primary)** |
| S25 | Komodo dPoW notarization | https://komodoplatform.com/en/blog/delayed-proof-of-work/ | C6 alternative family |
| S26 | Karakostas & Kiayias, *Securing Proof-of-Work Ledgers via Checkpointing* (2020) | https://eprint.iacr.org/2020/173.pdf | C1 formal framing |
| S27 | Eyal & Sirer selfish mining + Sapirshtein et al. optimal strategies | https://www.ifca.ai/fc16/preproceedings/30_Sapirshtein.pdf | **null — see §0.3** |

### 0.3 Sources read that yielded nothing usable (named nulls)

- **Eyal–Sirer uniform random tie-breaking (γ = ½, raising the selfish-mining
  threshold to 25%).** I searched specifically for a deployed chain that shipped
  uniform tie-breaking as a consensus or policy rule and **found none.** The
  literature treats it as a proposal; the record shows chains reaching instead for
  *freshness*-based rules (Horizen, PoP) rather than randomised tie-breaks. I am
  **not** proposing it as a candidate — a rule with no deployment record and a known
  liveness cost (it deliberately increases orphan rate and makes the honest network's
  own tip selection nondeterministic) fails the "reason from what broke" test. Noting
  it as a *considered and declined* item is the point.
- **Confirmation-depth guidance as a shipped consensus artifact.** I looked for a
  chain that put a recommended confirmation depth *into consensus*. Found none — it
  stayed exchange policy everywhere (Binance BTG 12 → 20; Bittrex VTC 600). This is a
  null with a consequence, folded into C8 instead of standing alone.
- **MIT DCI's 51%-attack page** did not itself carry per-incident depth/cost tables;
  the numbers below come from the Lovejoy writeups and press coverage, and are marked
  accordingly.

### 0.4 Verified vs. recalled

Every number below carries its source. Where I could not find a source, the line says
**UNVERIFIED** and I have not smoothed it into prose. Two specific cautions:

- **ETC January 2019**: press reports 219,500 ETC ≈ $1.1M double-spent (Coinbase's
  disclosure). I found this only in secondary reporting, not Coinbase's original post.
  Marked *secondary*.
- **Horizen's "~10× attack cost"** figure is the project's own claim from its own
  blog/whitepaper. I found no independent replication. Marked *self-reported*.

### 0.5 Scope discipline against the ratified posture

RandomX v2, LWMA-1, PQC and privacy are closed. Two candidates sit near a closed
boundary and say so explicitly rather than sneaking past it:

- **C3** hardens the *inputs* to the difficulty algorithm (timestamps). It does not
  change LWMA. If phase 2 judges otherwise, C3 should be rejected on that ground,
  not silently narrowed.
- **C13** touches block-verification cost, which interacts with RandomX verification
  time. It proposes no PoW change.
- **Merge-mining** comes up repeatedly in the Qubic material as a Monero mitigation.
  I am **not** proposing it — it is a PoW-structure change and the posture is closed.
  Flagged so phase 2 knows it was seen and set aside.

---

## C1. Maximum reorganisation depth (finality bound)

**1. The rule.** A node MUST NOT reorganise away a block buried more than `R` blocks
below its current tip. A competing branch forking below `tip − R` is rejected
regardless of its cumulative work. `R` is a fixed consensus constant, and the rule is
symmetric: it binds every node identically, with no operator opt-in and no external
data source.

**2. The threat it answers.** An adversary with transient majority hashpower — rented,
externally subsidised (the Qubic model: pay miners in another asset to redirect), or
simply borrowed from the RandomX CPU-miner population — mines a private branch, then
publishes it to reverse settled transactions. The motive is exchange double-spend:
deposit, trade out, reorg the deposit away. This is the single most-executed attack in
the 2018–2020 record. A genesis-stage RandomX chain is the ideal target: the hardware
is universal, the price is low so the defensive hashrate is low, and the attacker's
cost scales with *our* hashrate, not with theirs.

**3. The evidence.**

*Attacks:*
- **Vertcoin, Dec 2018** — 22 deep reorgs, 15 with double-spends; largest **307 blocks
  deep**, replaced by 310; >$100,000 total ([Nesbitt / Coinmonks](https://medium.com/coinmonks/vertcoin-vtc-is-currently-being-51-attacked-53ab633c08a4)).
- **Vertcoin, 1 Dec 2019** — **603 blocks removed**, 553 added; Bittrex's confirmation
  requirement at the time was 600, i.e. the attacker cleared the exchange's own
  threshold ([CoinDesk](https://www.coindesk.com/tech/2019/12/02/the-vertcoin-cryptocurrency-just-got-51-attacked-again)).
- **Bitcoin Gold, 23–24 Jan 2020** — two reorgs, ~14–15 blocks each; eight reorgs
  observed 23 Jan – 5 Feb, four with double-spends totalling ~12,858 BTG (~$150,000);
  **cost per reorg ≈ 0.2 BTC (~$1,700)** on NiceHash Zhash, roughly offset by the
  block rewards the attacker collected ([Lovejoy, MIT DCI](https://medium.com/mit-media-lab-digital-currency-initiative/reorgs-on-bitcoin-gold-counterattacks-in-the-wild-da7e2b797c21)).
  *This is the number that matters: the attack was self-financing.*
- **Ethereum Classic, Aug 2020** — three events reorganising **3,693**, ~**4,000**, and
  **>7,000** blocks; OKEx lost **$5.6M** ([CoinDesk 1 Aug](https://www.coindesk.com/markets/2020/08/01/ethereum-classic-suffers-reorganization-that-resembles-51-attack-amid-miner-complications), [CoinDesk 29 Aug](https://www.coindesk.com/markets/2020/08/29/ethereum-classic-hit-by-third-51-attack-in-a-month)).
- **Ethereum Classic, Jan 2019** — 219,500 ETC ≈ $1.1M (*secondary reporting only*).
- **Monero, Aug–Sep 2025** — 6-block reorg 12 Aug; **18-block reorg** at height
  3,499,659, ~118 transactions invalidated, ~36 minutes of history — the deepest in
  Monero's history ([CoinDesk](https://www.coindesk.com/web3/2025/09/15/monero-suffers-deepest-ever-blockchain-reorganization-invalidating-118-transactions)).

*Retrofits actually shipped, by name:*
- **Bitcoin Cash / Bitcoin ABC 0.18.5, Nov 2018 — "rolling 10-block checkpoints."**
  Blocks auto-finalise at 10 confirmations; deeper alternatives are refused even with
  more work ([BitMEX Research](https://www.bitmex.com/blog/bitcoin-cash-abcs-rolling-10-block-checkpoints)).
  This is the canonical shipped max-reorg-depth rule.
- **Ethereum Classic, 11 Oct 2020 — MESS (ECIP-1100), "Modified Exponential Subjective
  Scoring."** A *soft* depth limit: a proposed branch must carry up to **31×** the
  local branch's difficulty, the penalty ramping over ~25,132 s (~7 h) since the common
  ancestor ([ECIP-1100](https://ecips.ethereumclassic.org/ECIPs/ecip-1100)).
- **Monero, Sep 2025 — `--enforce-dns-checkpointing` / rolling DNS checkpoints**,
  proposed as an *opt-in emergency bandaid* ([monero#10064](https://github.com/monero-project/monero/issues/10064)).
  Still opt-in as of that thread; the objection recorded there is exactly the one below.
- Formal framing: Karakostas & Kiayias, *Securing PoW Ledgers via Checkpointing*
  ([ePrint 2020/173](https://eprint.iacr.org/2020/173.pdf)).

*And — this is the part usually left out — what happened to the retrofits:*
- **MESS was disclosed vulnerable.** VeriBlock told ETC devs in Oct 2020 (*before*
  mainnet activation) that MESS's subjectivity lets an attacker **permanently
  partition** the network into disjoint sets that never re-converge; cost estimated at
  ~$10K then, "<$50K" later. Their finding was that this is *inherent to subjective
  scoring*, not a parameterisation bug ([VeriBlock, Jul 2021](https://veriblock.org/veriblock-foundation-discloses-mess-vulnerability-in-ethereum-classic-blockchain/)).
- **MESS was deactivated** by ECIP-1110 in **January 2024**, on the stated ground that
  the hashrate circumstance it was built for (Ethereum PoW dwarfing ETC) ended when
  Ethereum merged to PoS in Sep 2022; ETC then held ~85% of its own algorithm's
  apparent hashrate supply, so MESS's costs exceeded its benefit ([ECIP-1110](https://ecips.ethereumclassic.org/ECIPs/ecip-1110)).
- **ECIP-1100 itself admits the split risk**: "if competing segments become available
  with near-equal total difficulty within the window … this bifurcated state shall be
  indefinite." It argues this is unlikely, not impossible.

**4. The trade.**

- **Permanent-split risk, and it is real, not theoretical.** BitMEX's analysis of ABC's
  rule: an attacker who diverges by >10 blocks can no longer reorg — but can *choose
  the publication moment* so that different nodes finalise different blocks, splitting
  the network into two coins. VeriBlock's MESS finding is the same shape for the soft
  variant. **A depth limit converts a reversible attack into an irreversible one.**
  Whether that is a good trade is a value judgement, not a technical one, and it should
  be recorded as such.
- **Nodes that were offline or resyncing are stranded.** BitMEX's sharpest point: the
  rule "enables sybil attack nodes not on the latest chaintip," and contradicts the
  premise that nodes may leave and rejoin at will. A phone wallet's node offline for a
  week is now dependent on which branch it sees first. For a chain with mobile wallets
  this is a first-order UX failure mode, not a footnote.
- **A deep reorg cannot be classified as attack-or-accident in real time.** ETC's
  3,693-block reorg on 1 Aug 2020 was *initially* reported as a miner running old
  software after being offline, and only later confirmed as a deliberate shadow-chain
  51% attack (see App. B.3). A depth limit has to fire — or not — in the seconds after
  the branch arrives, on exactly the information that turned out to be misleading here.
  It cannot wait for the forensics, and when it fires on a genuine accident the result
  is a permanent chain split with no attacker at all.
- **`R` has no principled value.** 10 (ABC) protects against nothing in the Vertcoin
  cases. 600 (Bittrex's VTC policy) was cleared by a 603-block reorg. Any `R` we pick is
  a guess dressed as a constant, and picking it wrong is unrecoverable post-genesis.
- **It needs a sunset condition or it outlives its reason.** ETC's experience is the
  lesson: the rule was correct in 2020 and wrong by 2024, and it took a governance
  process to remove it. Any depth limit Shekyl ships should carry a written,
  measurable deactivation criterion at birth — e.g. "when Shekyl's hashrate exceeds
  X% of the RandomX-capable hardware family for Y consecutive months." Shipping the
  rule without the sunset repeats ETC's mistake in the other direction.

**5. Confidence.** **High** that the *absence* is a genuine gap: no CryptoNote-lineage
codebase I am aware of enforces an unconditional depth limit, Monero's is opt-in and
DNS-sourced, and the incident record for minority chains of a large hardware family is
unambiguous. **Medium-low** that an unconditional hard depth limit is the right answer
— the retrofit record is genuinely mixed, one shipped version was disclosed vulnerable
and another was switched off. I would rate a **defence-in-depth pairing (C2 + C6 +
C8)** above a bare depth limit.

---

## C2. Late-block penalty in fork choice (publish-or-perish / uncle-aware weighting)

**1. The rule.** Chain weight is not the sum of difficulty alone. A block first seen
more than `D` seconds after another block of the same height contributes **zero** to
chain weight, and a block MAY commit (in its coinbase) to a competing "uncle" header at
its parent's height, which restores weight to the branch that acknowledged the
competitor. Beyond a lead of `k` blocks the rule releases and plain cumulative-work
resumes, so that a genuine network partition still heals.

**2. The threat it answers.** A miner with **well under 50%** withholds blocks, builds a
private lead, and releases in a burst to orphan honest work. The motive is not
double-spend but *revenue*: a share of blocks larger than their hashrate share, plus
the collateral effect of repeated shallow reorgs that make the chain feel unusable. The
actor is exactly the profile Shekyl faces — a large CPU pool, or an entity paying
miners in another asset to point at us. Under plain longest-chain, first-seen-wins
gives the withholder the tie-break advantage; a freshness rule takes it away.

**3. The evidence.**

- **Zhang & Preneel, "Publish or Perish: A Backward-Compatible Defense against Selfish
  Mining in Bitcoin," CT-RSA 2017** — the fork-resolving policy "neglects blocks that
  are not published in time and appreciates blocks that incorporate links to competing
  blocks of their predecessors," so a secret block "contributes to neither or both
  branches" ([PDF](https://www.esat.kuleuven.be/cosic/publications/article-2746.pdf), [eval code](https://github.com/nirenzang/Publish-or-Perish)).
- **Horizen (ZenCash), shipped Sep 2018 — the "delayed block submission penalty."**
  After a 51% double-spend against an exchange on 2 Jun 2018, Horizen published a
  whitepaper on 14 Jun, ran testnet 7 Sep, and shipped ZEN 2.0.15 to mainnet **24 Sep
  2018**. A block delayed ≥5 blocks behind the tip incurs a penalty that grows
  *quadratically* in the number of additional blocks the miner must produce before
  their branch is accepted. Claimed ~10× attack-cost increase (*self-reported*)
  ([Horizen blog](https://blog.horizen.io/horizens-51-attack-solution/), [CoinDesk](https://www.coindesk.com/tech/2018/10/10/a-solution-to-cryptos-51-attack-fine-miners-before-it-happens)).
  **This is a real, shipped, production retrofit and it is the strongest evidence in
  this whole document.** (I verified the Sep 2018 ship; I did **not** re-verify that
  the rule is still active in Horizen today — phase 2 should confirm current status
  before the "it has run in production for years" claim is used in an argument.)
- **Monero, Aug 2025 — tevador's Publish-or-Perish, research-lab issue #144.** Read the
  spec, because it is an exact template for a CryptoNote-shaped chain:
  - "Late" = arriving **> D = 5 s** after another block of the same height. Uses
    **relative arrival order only** — no absolute clock agreement required.
  - Late blocks contribute no chain weight; the rule applies while the attacker's lead
    is **< k = 3** blocks, then reverts to longest-chain so partitions resolve.
  - New `tx_extra` tag carries an **uncle** — the ~80-byte PoW header of a block at
    height N−1, validated by matching `prev_id` against the canonical N−1.
  - Modelled effect: at α = 0.48 the attacker's reward share falls from ~88% to ~64%.
  - The hard-fork extension adds **reward splitting**: block N's reward is paid from
    N−20 and split between the N miner and every miner whose uncle at height N appears
    in N+1…N+20; claimed to remove the selfish-mining incentive entirely unless the
    attacker can out-mine the honest set by ≥20 blocks. It also moves block time to 60 s
    and coinbase maturity to 1440 blocks.
  - Explicit limit stated by the author: it "does not (and cannot) address 51% attacks";
    it assumes α < 0.5.
  - Notable design constraint recorded there: Fruitchain-style frequent-hashrate-sampling
    defences were **disqualified because RandomX is too slow to verify** — a block with
    100 work shares would need ~1.5 s of PoW verification alone. *This constraint applies
    to Shekyl identically and is worth carrying forward (see C13).*
  ([monero-project/research-lab#144](https://github.com/monero-project/research-lab/issues/144))
- **Measured attack, same period:** the Qubic campaign averaged **23.38%** of Monero
  hashrate overall and **28.33%** during identified selfish-mining periods; ten
  withholding periods identified Aug–Oct 2025; multi-block forks replaced the normal
  single-block orphan pattern. Notably the campaign was **not profitable** — 3,239
  accepted blocks across P1–P10, a target-rate-normalised shortfall of 3.22 percentage
  points, and after crediting 461.8 block-equivalents of difficulty-adjustment
  spillover still **460 blocks below the honest baseline, a 4.0% deficit** (quoted as
  stated in the paper; I did not reconstruct the baseline arithmetic) —
  and Qubic sometimes mined competing blocks on the same parent, wasting its own work
  ([arXiv 2512.01437](https://arxiv.org/html/2512.01437)).
  **[Phase-2 editorial marker, 2026-09-03: the +461.8 spillover credit and the −460.0
  deficit are *separate ledger lines* of near-equal magnitude — this sentence chains
  them causally, and they must not be read as one number netted. Verified against the
  paper; the decompression is recorded in
  [`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §12's spot-check paragraph.]**

**4. The trade.**

- **Fork choice becomes partly subjective.** Two honest nodes with different network
  vantage points can disagree on which block was "late." The `k`-block release valve
  exists precisely to bound this, but it means the rule is a *delay*, not a *bar*, and
  a well-connected attacker degrades it.
- **Higher orphan rate on the honest chain.** Any freshness rule penalises slow
  propagation, which is a tax on geographically distant and Tor-routed miners. For a
  privacy chain where miners may be behind onion transports, this is a
  decentralisation cost paid by exactly the participants we most want.
- **Uncle commitments enlarge the coinbase and the validation surface.** ~80 bytes per
  uncle plus a new consensus-validated field, and the reward-splitting variant makes
  the coinbase reward a function of the *next* 20 blocks — a substantial complication to
  emission accounting, wallet balance display, and any staking/bond logic keyed to
  coinbase.
- **The reward-splitting variant is a much bigger change than it looks:** it moves
  coinbase maturity to 1440 and reshapes the difficulty calculation to include uncles.
  If it is wanted, it must be at genesis; retrofitting is a hard fork with an emission
  discontinuity.
- **Attackers adapt operationally.** Qubic responded to observation by encrypting
  solution messages, rotating the encryption, changing routing, and withholding
  transactions from templates until publication — defeating the community's real-time
  block reconstruction. A rule that depends on *observing* the attacker degrades; one
  that depends only on *arrival order at each node* (as PoP does) degrades less. Prefer
  the latter.

**5. Confidence.** **High** that this is absent from a CryptoNote-derived tree — Monero
itself does not have it, which is why it was proposed in Aug 2025 and is still a
proposal. **High** that it is worth doing: it is the only candidate here with a
production deployment (Horizen, shipped Sep 2018; current status not re-verified),
a peer-reviewed root (CT-RSA 2017), *and* a spec already written against CryptoNote's
exact data structures. For a
genesis-stage chain the hard-fork variant is available for free — we have no legacy.

---

## C3. Timestamp discipline: monotonicity, a tight future-time limit, and bounded past-drift

**1. The rule.** Three linked constraints on every block's timestamp:
(a) **monotonic** — `prev_timestamp < this_timestamp`, no exceptions and no
median-window escape hatch; (b) **tight future limit** — `this_timestamp < local_time +
FTL` with `FTL` on the order of a few hundred seconds, not 7200, and `FTL` small
relative to the difficulty averaging window; (c) **bounded backward drift** — a
symmetric-ish past limit so a block cannot claim a timestamp far behind its parent, and
the difficulty code clamps solvetimes at both ends rather than zeroing negatives.

**2. The threat it answers.** A miner — and per the analysis below, one with well under
50% — forges timestamps to drive difficulty down, then mines the deflated chain at
enormous multiples of their true share. The motive is direct inflation (mint coins
cheaply) or the manufacture of a long private branch at negligible cost, which then
feeds every other attack in this document. This is *not* an exotic attack; it is the
attack that actually happened to a top-30 coin, twice, in six weeks.

**3. The evidence.**

- **Verge (XVG), Apr–May 2018 — hit twice.** From 4 Apr to 22 May 2018 an attacker
  mined blocks with spoofed timestamps to force difficulty down. April: ~250,000 XVG
  taken. Mid-May, after the first patch, the attacker adapted by **alternating two of
  Verge's PoW algorithms** (five blocks on each) and repeated the same timestamp
  exploit; reported at ~$1.7M. The fix Verge eventually shipped was to **limit the
  block drift window to ten minutes from block 2,040,000** — i.e. an FTL reduction
  ([CoinDesk](https://www.coindesk.com/markets/2018/06/05/verges-blockchain-attacks-are-worth-a-sober-second-look), [Apriorit teardown](https://www.apriorit.com/dev-blog/563-verge-mining-hack)).
  *The "patched once, re-exploited six weeks later" shape is the important part: a
  partial timestamp fix is not a fix.*
- **zawy12, "Timestamp Attacks" (difficulty-algorithms #30)** — the single densest
  source in this corpus. It enumerates twelve vectors and states four requirements. The
  ones that bear directly:
  - *"Secure distributed consensus isn't possible without monotonic timestamps"* —
    `previous_timestamp < allowable_timestamp < local_time + FTL` must hold for **all**
    blocks.
  - **Reverse-timestamp attack**: with out-of-sequence timestamps mishandled, an
    attacker needs **as little as >17%** hashrate (at MTP=11) to drive difficulty toward
    zero over ~6 blocks.
  - **MTP attack**: **25%** hashrate controlling 6 of the last 11 blocks can push
    timestamps to the FTL and block honest miners.
  - **CryptoNote defaults are called out by name**: "Cryptonote coin default has MTP=60
    which makes it easy" — a larger median window *reduces* the hashrate an attacker
    needs, from ~93% at MTP=11 to feasible levels at MTP=60. Also flagged: no
    peer-time restriction, and no timespan limit ("throw a negative difficulty").
  - FTL guidance: **FTL < N·T/20** (window/20) to cap per-block manipulation at ~5%;
    "FTL < N·T/10 prevents >10% difficulty manipulation via a single block"; FTL should
    still exceed ~2× typical propagation delay.
  ([issue #30](https://github.com/zawy12/difficulty-algorithms/issues/30))
- **zawy12, "Handling Bad Timestamps" (#13)** — quantifies the CryptoNote default:
  with **FTL = 7200 s**, a miner with 2× the network hashrate can take **~60 blocks
  without difficulty adjusting**, by assigning timestamps of
  `(HR+P)/P · T + previous_timestamp`. Recommends FTL = **max(300, T·N/20)**, and
  solvetime clamping (`ST > 6T → 6T`, `ST < −5T → −5T`) rather than the common
  `if ST < 0 then ST = 0` pattern — which, combined with asymmetric limits, lets a
  **20%** miner halve difficulty within one window. Names **Graft** as the real-world
  case where FTL was not reduced from 7200 ([issue #13](https://github.com/zawy12/difficulty-algorithms/issues/13)).
- **LWMA coins attacked, Apr 2018** — Niobio, Intense, Karbo, Sumo; "in an hour or two
  attacker could lower difficulty to 1/100,000th" (#30). *This is direct evidence that
  choosing LWMA does not by itself close the timestamp surface.*
- **Bitcoin is still shipping timestamp rules in 2024–25.** The Great Consensus Cleanup
  timewarp fix, revived by Poinsot in 2024, restricts cross-retarget timestamp
  manipulation; Poinsot's argument is that a 51% attacker exploiting timewarp could
  "prevent all Bitcoin usage within 40 days" without holding continuous majority
  ([bitcoindev thread](https://groups.google.com/g/bitcoindev/c/CAfm7D5ppjo)). The
  equivalent rule shipped on testnet4 as **BIP94**, and the threshold was deliberately
  moved **back to 600 s from 7200 s** because 7200 "allowed for some nonzero inflation"
  ([bitcoin#30647](https://github.com/bitcoin/bitcoin/pull/30647)).
- **Zcash, Feb 2020** — a security patch introduced an MTP-based FTL vector enabling
  **>25% increased emission** (#30). Cited as a caution that timestamp changes are easy
  to get subtly wrong.

**4. The trade.**

- **Strict monotonicity can stall a chain.** If a block arrives with a timestamp at the
  FTL ceiling, the next block must be strictly later — under a tight FTL this can force
  miners to wait. This is the mechanism behind bitcoin#30681/#31376 having to teach the
  *miner* about the timewarp rule so it never builds an unmineable template. Any
  monotonicity rule must be paired with template-construction logic, or the chain
  wedges itself with no attacker present.
- **Tight FTL punishes bad clocks.** With FTL ≈ 300 s, a miner whose clock is off by
  ten minutes produces blocks everyone rejects, and *they will not know why*. This is a
  real operator-facing failure mode (see also C5: without peer-time adjustment, the
  node cannot self-correct). It demands an explicit, legible diagnostic — "your system
  clock is N seconds fast; blocks will be rejected" — not a silent reject.
- **Tight FTL narrows the propagation margin.** zawy's own floor is FTL > 2× typical
  propagation delay. On a Tor-heavy privacy network, "typical propagation delay" is
  larger and more variable than on a clearnet chain, so the safe FTL floor for Shekyl
  is higher than 300 s and needs measuring, not assuming.
- **Backward-drift limits interact with LWMA's window.** Clamping solvetimes changes
  the difficulty response to genuine hashrate cliffs — which a minority chain will have.
  Clamp too tight and the chain is slow to recover when hashrate leaves.
- **Boundary note:** this hardens the DAA's *inputs*. It does not replace LWMA-1 and
  does not reopen the LWMA-vs-ASERT decision. If phase 2 reads it as reopening that
  decision, reject C3 explicitly on that ground.

**5. Confidence.** **High.** The CryptoNote defaults are named as vulnerable by the
best-known source on the subject; the attack has been executed against real coins
including LWMA coins; and two separate ecosystems (Bitcoin 2024–25, Verge 2018) shipped
FTL/timewarp restrictions after the fact. Of everything here, this is the candidate
most likely to be *partially* present (some chains reduce FTL and stop there) and least
likely to be *fully* present.

---

## C4. Time-locked spendability must be evaluated against median-time-past, never a block timestamp

**1. The rule.** Any consensus predicate of the form "this output is spendable after
time T" — CryptoNote's `unlock_time` in its timestamp interpretation, and any
stake/bond/archival maturity keyed to wall-clock — MUST be evaluated against the
**median timestamp of the previous N blocks**, not against the including block's own
timestamp and not against the node's local or network-adjusted clock.

**2. The threat it answers.** A single miner chooses their own block's timestamp,
subject only to the future-time limit. If timelocks are evaluated against that
timestamp, **one miner can unilaterally accelerate every wall-clock timelock on the
chain by up to the FTL** — 2 hours under CryptoNote defaults. Motive: collect fees from
not-yet-mature transactions; or, more seriously for Shekyl, mature a stake/bond
withdrawal, an escrow, or a recovery path ahead of schedule. This is *not* a 51%
attack — it needs one block.

**3. The evidence.**

- **BIP113, "Median time-past as endpoint for lock-time calculations"** — shipped in
  Bitcoin Core 0.11.2 (2015) as policy and activated as consensus with the CSV soft
  fork (2016). Its stated rationale is exactly this: because a block's timestamp may be
  up to ~2 hours ahead, evaluating locktime against it "creat[es] a perverse incentive
  for miners to lie about the time of their blocks in order to collect more fees by
  including transactions that by wall clock determination have not yet matured."
  BIP113 changes the endpoint to the median of the previous 11 blocks, which "existing
  consensus rules guarantee … to monotonically advance," so a single miner cannot move
  it and a colluding group can only shift it by a bounded amount
  ([BIP113](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki), [bips.dev/113](https://bips.dev/113/)).
- **CryptoNote never adopted the equivalent.** CryptoNote's `unlock_time` field, when
  above the height/timestamp discriminator, is a wall-clock timestamp. I could not find
  any CryptoNote-lineage BIP113 analogue in the public literature. **This is the
  cleanest "rule that should exist and probably doesn't" in the whole document**: a
  named, decade-old Bitcoin fix with a documented rationale, and no CryptoNote counterpart.
- **Reinforcing:** zawy #30's requirement that consensus-relevant time be monotonic is
  the same argument arriving from the difficulty side.

**4. The trade.**

- **MTP lags real time by roughly half the window.** With N=11 at 2-minute blocks that
  is ~11 minutes; with CryptoNote's habit of N=60 it is over an hour. A user setting
  "spendable at 3pm" gets "spendable when the chain's median says 3pm," which may be
  later in wall-clock terms. That is a **UX cost that must be surfaced** — a wallet must
  not silently show a lock as expired when consensus disagrees, and must not promise
  wall-clock precision it cannot deliver.
- **Two clocks in the system.** MTP for consensus, wall-clock for display, and the gap
  between them is a permanent source of "why can't I spend this yet" support load.
- **Interacts with C3.** MTP is only monotone if timestamps are constrained; the two
  rules are a pair, and shipping C4 without C3 buys less than it appears to.
- **Cheap, though.** Unlike most candidates here this one has essentially no
  liveness cost, no split risk, and no attacker-facing complexity. Its cost is UX and a
  window-size choice.

**5. Confidence.** **High** on the gap. **Medium-high** on severity: it depends on
whether Shekyl actually exposes wall-clock timelocks (CryptoNote's `unlock_time`,
staking/bond maturity, archival windows). If every maturity in the system is
height-based, C4 collapses to "make sure it stays that way" — which is still a rule
worth writing down, because the pressure to add a timestamp-based lock will come later.

---

## C5. The node's clock is local and independent — no peer-supplied time adjustment

**1. The rule.** A node's notion of "now," used for the future-time limit and any other
consensus-adjacent time check, MUST come from its own system clock alone. It MUST NOT
be adjusted by a median of peer-reported times, and MUST NOT depend on an agreed NTP
service reachable over the same network path as the P2P layer.

**2. The threat it answers.** An eclipsing or Sybil adversary feeds a victim node a
skewed peer-time. If the node's FTL is computed against that skewed clock, the attacker
can make the victim accept blocks the honest network rejects (or reject blocks the
honest network accepts) — splitting the victim from consensus without any hashrate at
all. Motive: isolate a merchant or exchange node to make a shallow double-spend look
confirmed; or freeze a node after reboot. The actor needs peers, not hashpower — which
makes it *cheaper than every other attack here.*

**3. The evidence.**

- **zawy #30, requirement 2**: "Nodes must maintain autonomous time measurement without
  consulting peers or agreed-upon NTP services to prevent Sybil/eclipse attacks." The
  same document lists **"Node Peer Time Attack"** (Sybil the peer-time consensus to
  isolate merchants or block honest miners) and **"Peer Time/Database Attack"**
  (combined Sybil + future timestamps to freeze nodes post-reboot) among its twelve
  vectors, and specifically notes that **CryptoNote defaults lack the peer-time
  restriction Bitcoin has** ([#30](https://github.com/zawy12/difficulty-algorithms/issues/30)).
- Bitcoin's own network-adjusted-time mechanism is capped (±70 minutes, and it only
  ever *warns*), which is itself an acknowledgement that peer time is untrusted input;
  the cap is the mitigation, not the design. zawy's position is that the right answer is
  to drop the peer input entirely.
- The eclipse-attack literature (Heilman et al., USENIX Security 2015, for Bitcoin;
  Marcus, Heilman & Goldberg, 2018, for Ethereum) establishes that eclipsing a node is
  practical. **UNVERIFIED in this session** — I did not fetch either paper and am
  citing them from memory; phase 2 should pull them if this candidate is pursued.

**4. The trade.**

- **A node with a wrong clock now has no self-correction.** Combined with C3's tight
  FTL, a machine whose clock drifts (a Pi with no RTC and no network time, say — and
  the stated device floor is a Pi 4) will silently fall out of consensus. The rule
  therefore *requires* a loud local diagnostic and probably a startup sanity check
  against the chain's own MTP, which is itself a weak form of peer time. There is a
  genuine circularity here and it should be designed, not hand-waved.
- **It shifts the burden to the operator.** "Keep your clock right" is a real support
  cost, and on mobile/embedded it is not always in the user's control.
- **Low implementation cost, high documentation cost.** The code change is removing an
  input; the work is in the failure-mode UX.

**5. Confidence.** **Medium-high** on the gap (zawy names CryptoNote's missing
peer-time restriction explicitly, though he frames Bitcoin's *presence* of peer time as
the flaw and CryptoNote's absence of a *restriction* as a different flaw — phase 2
should read #30 directly rather than trusting my compression). **Medium** on priority:
it is cheap and it closes a no-hashrate attack, but it only bites in combination with C3.

---

## C6. Stake-quorum block finality (a ChainLocks-shaped rule), given that a staking system already exists

**1. The rule.** At each height, a deterministically-selected quorum drawn from the
active stake set signs the **first** block it sees extending the active chain. If a
threshold of the quorum (Dash uses ≥60% of a 400-member quorum) signs the same block, a
signature message is propagated and every node then rejects all other blocks at that
height and all their descendants — making reorgs below that block impossible, at one
confirmation.

**2. The threat it answers.** The same majority-hashpower double-spend as C1, but the
defence is anchored in a resource the mining adversary **does not** hold. A RandomX 51%
adversary can rent or redirect CPU; they cannot rent the staked supply without buying
it, and buying it is the one cost that scales with the chain's value rather than with
its hashrate. This directly inverts the structural problem in Shekyl's stated posture:
*hashrate security is cheap for the attacker at genesis, but stake is not.*

**3. The evidence.**

- **Dash ChainLocks, DIP-0008, shipped in Dash Core 0.14 (2019).** "For each block, an
  LLMQ of a few hundred masternodes is selected and each participating member signs the
  first block that it sees extending the active chain at the current height. If enough
  members (≥60%) see the same block … they create a CLSIG message." On receipt, a node
  "should reject all blocks (and their descendants) at the same height that do not match
  the block specified in the CLSIG," which "makes reorganizations below this block
  impossible." Signing uses the `LLMQ_400_60` quorum type
  ([DIP-0008](https://github.com/dashpay/dips/blob/master/dip-0008.md), [Dash blog](https://medium.com/dash-org/mitigating-51-attacks-with-llmq-based-chainlocks-7266aa648ec9)).
  Framing it as "a verifiable network-wide measurement of the first-seen rule" is the
  useful mental model, and it is a much better one than "checkpoint."
- **ChainLocks was named as an option in the post-Qubic Monero discussion**, alongside
  temporary DNS checkpointing, consensus-algorithm changes and merge mining.
  **Citation discipline:** this comes from *contemporaneous press coverage of the
  debate*, not from monero#10064 itself — my fetch of that issue found it discusses
  parameters and objections for rolling DNS checkpoints and does **not** compare
  ChainLocks, publish-or-perish, merge mining, or depth limits. Phase 2 should ground
  the "ChainLocks was on Monero's table" claim in the MRL meeting logs
  ([monero-project/meta#1288](https://github.com/monero-project/meta/issues/1288)) if
  it matters. **And the next sentence is my inference, not a sourced claim:** Monero
  cannot deploy a ChainLocks-shaped rule because it has no staking layer to draw a
  quorum from — Shekyl does. If that inference holds, this is the clearest instance in
  the corpus of a defence unavailable to Monero and available to us.
- **The alternative family — external anchoring — is worth naming for contrast.**
  Komodo's **dPoW** notarises a block hash from each protected chain onto KMD, and a KMD
  hash onto Litecoin/Bitcoin, via 64 elected notary nodes; rewriting history then
  requires overpowering the anchor chain too. Credited with stopping a $1.23M attack on
  Aryacoin in Sep 2020 ([Komodo](https://komodoplatform.com/en/blog/delayed-proof-of-work/)).
  I am **not** recommending dPoW — it imports a permanent dependency on a foreign chain
  and an elected notary set, which contradicts a "must outlast the team" posture. But
  it establishes that "borrow security from a non-hashrate resource" is a deployed
  pattern, not a novelty.

**4. The trade.**

- **At genesis the stake set is tiny, and that is exactly when this rule is most
  needed.** A quorum drawn from a small, possibly founder-dominated stake set is a
  centralisation vector wearing a decentralisation costume. This rule may need an
  activation threshold (minimum staked supply, minimum distinct stakers) below which it
  does not apply — which means it is *off* during the window C1 was written for. That
  tension is the main argument for shipping C1 **and** C6 as a pair with complementary
  activation conditions, not as alternatives.
- **It introduces a liveness dependency.** If the quorum cannot reach threshold — network
  partition, a coordinated stake-holder outage — the chain either stalls or falls back to
  plain PoW, and the fallback path is itself an attack target (force the fallback, then
  reorg).
- **It is a non-PoW authority over fork choice.** Whatever the framing, a stake quorum
  can now veto a valid-by-work chain. That is a genuine change to what the chain *is*,
  and it deserves to be argued on its merits rather than smuggled in as an
  anti-51% measure. It also creates a coercion target: a small identified quorum is
  subpoenable in a way that anonymous hashrate is not — which cuts against the privacy
  posture in a way worth stating out loud.
- **Substantial complexity**: quorum selection, threshold signatures (and PQ threshold
  signatures are not a solved, off-the-shelf thing — this interacts with the PQC
  commitment in a way I cannot assess from outside the tree), signature propagation, and
  a whole new consensus message type.

**5. Confidence.** **Medium-high** that it is absent (a chain would not usually build
this at genesis). **High** that it is the most *interesting* candidate here, because it
is the only one that uses an asset Shekyl already has against the specific structural
weakness Shekyl has declared. **Medium** that it should ship — the genesis-window
chicken-and-egg is severe and the PQ threshold-signature question could be
disqualifying. Phase 2 should treat "can we even do a PQ threshold signature over a
rotating quorum" as the gating question.

---

## C7. Anti-DoS sync: bounded header acceptance, minimum chain work, and `assumevalid` — *not* checkpoints

**1. The rule.** Three separable things, none of which is a checkpoint:
(a) a node MUST NOT commit headers to permanent storage until the presented chain
demonstrates cumulative work above a threshold (Bitcoin's headers-presync);
(b) `nMinimumChainWork` — a node in initial sync does not request blocks from a peer
whose tip is below a hardcoded work floor;
(c) `assumevalid` — script/proof verification may be skipped for ancestors of a
configured known-valid block, **without** influencing fork choice.

**2. The threat it answers.** (a) and (b): an attacker with negligible hashpower feeds a
syncing or restarting node a long chain of trivially-mined low-difficulty headers,
exhausting its memory or simply wasting its bandwidth — and, on a young chain where the
real difficulty is also low, potentially winning the node's fork choice outright. Motive:
crash competing miners, or eclipse a merchant into accepting a fake chain. (c) is not a
security rule at all but a sync-time optimisation, and the reason to name it here is to
**stop it being confused with a checkpoint** during design.

**3. The evidence.**

- **CVE-2019-25220 — headers-spam memory DoS in Bitcoin Core**, publicly disclosed
  18 Sep 2024. Before v24.0.1 an attacker could crash peers by making them store
  arbitrarily long chains of low-difficulty headers in memory. **Attack cost fell from
  ~4.12 BTC (Oct 2019) to ~1.07 BTC (Feb 2022) to ~0.14 BTC (Sep 2024)** — the cost of
  this attack *decreases* as difficulty history accumulates cheaply-mineable eras
  ([Bitcoin Core disclosure](https://bitcoincore.org/en/2024/09/18/disclose-headers-oom/)).
- **Fix: bitcoin/bitcoin#25717, "p2p: Implement anti-DoS headers sync"** (sdaftuar,
  in v24.0) — a presync phase downloads a peer's headers and verifies cumulative work
  *before* storing them permanently, then redownloads for full validation
  ([PR #25717](https://github.com/bitcoin/bitcoin/pull/25717)).
- **`assumevalid`, Bitcoin Core 0.14.0 (2017).** The release notes state the property
  that matters: *"Unlike checkpoints, this setting does not force the use of a
  particular chain: chains that are consistent with it are processed quicker, but other
  chains are still accepted if they'd otherwise be chosen as best."* Also unlike a
  checkpoint, the **user** can configure it ([Bitcoin Core 0.14.0](https://bitcoincore.org/en/releases/0.14.0/), [PR #9484](https://github.com/bitcoin/bitcoin/commit/812714f)).
  `nMinimumChainWork` is the companion: a floor on total work before a chain is
  considered at all ([PR #9779](https://github.com/bitcoin/bitcoin/pull/9779)).

**4. The trade.**

- **`nMinimumChainWork` is meaningless at genesis and stays weak for years.** The whole
  mechanism assumes the honest chain has accumulated work an attacker cannot cheaply
  match. For a zero-hashrate genesis chain the work floor is ~0 and rises slowly. So
  (b) buys almost nothing in year one, which is when it is needed. Saying so is the
  honest version of this candidate.
- **The bootstrapping trust has to go *somewhere*.** If not a work floor, then hardcoded
  checkpoints (Monero's approach, with all of C1's objections), or `assumevalid`-style
  release-shipped hashes, or nothing. Each is a different distribution of trust and none
  is free. `assumevalid` is the safest of them precisely because it cannot force a
  rollback — but it also does not *defend* anything; it only makes sync faster.
- **The presync path is real complexity in the P2P layer** and has its own failure modes
  (a peer that stalls presync, redownload cost).
- **Configurability cuts both ways.** A user-settable `assumevalid` means a user can set
  it wrong; a shipped default means users trust the release process. This is a
  distribution/trust question as much as a code question.

**5. Confidence.** **Medium-high** that the header-storage bound (a) is absent — it is a
2022-era Bitcoin fix and CryptoNote's sync path predates it by years. **High** that the
*conceptual* distinction in (c) is worth writing into the design doc regardless of code
state, because "add a checkpoint" is the reflex answer to C1 and this is the record of
why that reflex is wrong.

---

## C8. Every maturity, bond, and lock window must be defined against the finality bound — and exceed it

**1. The rule.** Coinbase maturity, stake/bond lock and unlock windows, archival
commitment windows, and any other consensus timer must be expressed in terms of the
chain's stated reorg-resistance depth `R`, and must be **strictly greater** than it.
Concretely: `coinbase_maturity > R`, `bond_unlock_delay > R`, and no consensus timer may
have a window shorter than `R`.

**2. The threat it answers.** A reorg deeper than a maturity window lets the same value
be spent on both branches. The classic case is coinbase: if maturity is 60 and a 100-
block reorg occurs, coinbase outputs spent on the losing branch had already been
credited. The Shekyl-specific case is worse and is the reason this is its own candidate:
a **staking/bond system** has its own timers, and if a bond can be posted, used, and
unlocked inside `R`, then a deep reorg lets the same stake back two conflicting
histories — which is precisely the failure mode C6 was meant to prevent, reintroduced
through the back door. Actor: any attacker already capable of a deep reorg; motive: the
reorg becomes free because the collateral is recoverable on both branches.

**3. The evidence.**

- **Coinbase maturity exists for exactly this reason** and every Bitcoin-lineage chain
  has it (100 blocks in Bitcoin; CryptoNote's default mined-money unlock window is 60).
  It is the oldest reorg-safety margin in the field.
- **The observed reorg depths blow through typical maturity windows.** Vertcoin's 307-
  and 603-block reorgs (§C1) exceed any coinbase maturity in common use. Bitcoin Gold's
  14–15 block reorgs exceeded **Binance's 6-confirmation deposit credit** and its
  12-confirmation withdrawal escrow, which is why **Binance raised BTG to 20
  confirmations** afterwards ([Lovejoy](https://medium.com/mit-media-lab-digital-currency-initiative/reorgs-on-bitcoin-gold-counterattacks-in-the-wild-da7e2b797c21)).
  The pattern is: *somebody's window was shorter than the reorg, every single time.*
- **tevador's PoP hard-fork variant moves coinbase maturity to 1440 blocks** while
  reducing block time to 60 s ([research-lab#144](https://github.com/monero-project/research-lab/issues/144))
  — i.e. a serious proposal from 2025 treats maturity as a *tunable safety margin* to be
  raised, not an inherited constant.
- **Named null (see §0.3):** no chain put a recommended confirmation depth into
  consensus. It stayed exchange policy, and exchange policy was wrong (Bittrex's 600 vs
  Vertcoin's 603). If Shekyl wants integrators to get this right, the chain has to
  publish `R` as a *first-class, versioned protocol constant* they can read — which is
  itself an argument for C1 existing at all.

**4. The trade.**

- **Long maturities are a real cost to miners** — capital locked, and for small CPU
  miners at genesis it may be the difference between mining and not. Raising coinbase
  maturity to exceed a large `R` directly worsens the hashrate problem this whole
  document is about. That is a genuine circular tension and there is no clean resolution.
- **It couples otherwise independent subsystems.** Staking, archival, and base
  consensus now share a constant, and changing `R` post-genesis means changing all of
  them together. That is a *good* property for correctness and a bad one for agility.
- **If `R` is not adopted (C1 rejected), this rule needs a different anchor** — e.g.
  "the deepest reorg the design is willing to survive," stated as a documented number
  even if not enforced. The rule survives C1's rejection; only its name changes.

**5. Confidence.** **Medium** on the gap for coinbase specifically (some maturity almost
certainly exists). **High** on the gap for the *cross-subsystem invariant* — the claim
that staking/archival windows are checked against the same bound as coinbase is exactly
the kind of thing that has no single code site and therefore would not appear in a
file:line census. This is the candidate I would most expect a line-anchored enumeration
to have missed structurally.

---

## C9. Fork activation must not be decided by hashrate voting

**1. The rule.** Consensus-rule activation is by height (or by a signal that a
majority-hashpower adversary cannot forge), never by a tally of miner votes carried in
block headers. If a voting mechanism exists in the codebase at all, it must be
unreachable — not merely unused.

**2. The threat it answers.** Shekyl's stated posture is that a motivated adversary has
51% capability for the chain's early years. Under a hashrate-voted activation rule, that
same adversary can (a) **activate** a rule change the community has not agreed to, or
(b) **veto** one it has, indefinitely, by withholding votes. Motive: forcing a fork that
splits the community, or blocking the deployment of the very anti-51% rules in this
document. The second is the sharper risk — an attacker who can veto activation can
prevent Shekyl from responding to being attacked.

**3. The evidence.**

- **Monero carries a hashrate-voting mechanism.** The block's *minor* version field is a
  vote; a window of 10,080 blocks (one week) is tallied, and a fork activates when the
  vote share exceeds a threshold, default **80%**, provided the height is also reached
  ([Monero Book, Hard Forks](https://monero-book.cuprate.org/consensus_rules/hardforks.html), [hardfork.h](https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/hardfork.h)).
  Crucially, the Monero Book states: *"Although it has never been used, Monero has a
  system in its codebase to allow voting for activation of a hard-fork … you don't need
  to implement it, but as it's included in the codebase, an explanation is included
  here."* **An unused-but-present activation path inherited into Shekyl is live
  attack surface with no test coverage.**
- **Bitcoin's miner-signalling experience is the deployment record.** BIP9 signalling
  gave miners an effective veto over SegWit, resolved only by BIP148 (UASF) and the
  political crisis around SegWit2x in 2017; the ecosystem's structural answer was
  **BIP8 with LOT=true**, which makes activation happen at a timeout regardless of miner
  signalling. **UNVERIFIED in this session** — I did not fetch BIP8/BIP148 and am
  citing the episode from memory; phase 2 should ground it if the candidate is pursued.
  The *direction* of the fix (remove the miner veto) is not in doubt.

**4. The trade.**

- **Height-based activation removes the readiness signal.** Miner voting, whatever its
  flaws, told you whether the network was ready. Flag-day activation risks activating
  into an unprepared ecosystem, and the failure mode is a chain split among *honest*
  participants.
- **Deleting the mechanism is a one-way door.** If a future maintainer wants
  hashrate-conditioned activation, they must re-add it. Given the "outlast the team"
  commitment, that is arguably correct — a future maintainer should have to justify it
  rather than inherit it.
- **Low cost, though.** This is the cheapest candidate in the document: it is a deletion,
  plus a test asserting the path is unreachable. Its cost is almost entirely the
  argument, not the code.

**5. Confidence.** **Medium-high** that the mechanism is inherited (Monero's is
documented as present-but-unused, and present-but-unused is exactly what gets carried
across a fork). **High** that if present it should go, given the stated posture — a
chain that assumes a 51%-capable adversary cannot hand that adversary a governance lever.

---

## C10. A launch-phase emission ramp (slow start)

**1. The rule.** Block subsidy rises linearly from a small fraction to full value over
the first `S` blocks, with the emission curve adjusted so the long-run schedule is
unchanged.

**2. The threat it answers.** Two, sharing one mechanism. (a) **Instamine**: at genesis
the chain's difficulty is a guess and the available hardware is enormous — every RandomX
CPU miner on earth can retarget in minutes. Whoever shows up first mines an outsized
share of supply at trivial cost. (b) **Bug blast radius**: if a consensus or emission
bug ships, the amount of value minted before it is caught is bounded by the ramp. The
actor for (a) is an opportunistic large pool or the attacker of C1 collecting subsidy as
they go; note from §C1 that the BTG attacker's *block rewards roughly paid for the
attack* — a slow start directly attacks that self-financing property.

**3. The evidence.**

- **Zcash, Oct 2016 — "slow-start mining."** Block reward ramped linearly over the first
  **20,000 blocks** (~34 days) to the full 12.5 ZEC. Stated purposes: avoid the
  Litecoin-style situation where early mining power vastly exceeds the initial
  difficulty setting, and — explicitly — *"in the event of a major bug or security
  vulnerability in the protocol, the slow-start minimized the impact."* It produced
  125,000 ZEC instead of 250,000 over the window, and the first halving interval was
  extended by 10,000 blocks so the monetary curve was preserved
  ([zcash#762](https://github.com/zcash/zcash/issues/762), [ECC blog](https://blog.z.cash/slow-start-and-mining-ecosystem/)).
- The instamine failure mode it was designed against is well documented across the
  2013–2014 altcoin era; I did not find a single canonical postmortem and am not citing
  one.

**4. The trade.**

- **It reduces the very incentive that would bring honest hashrate to a new chain, at
  the moment the chain most needs hashrate.** This is the direct tension, and it is not
  small: a slow start makes the first month less attractive to *everyone*, honest and
  hostile alike. Whether that is net-positive depends on whether the marginal early
  miner is more likely honest or hostile — and Shekyl's own posture says the hostile
  population is large.
- **It is genesis-only and irreversible.** There is no retrofit. Either it is in the
  emission schedule at block 0 or the option is gone forever.
- **It complicates the emission curve** and every derived artifact (supply charts,
  halving math, any economics constants derived from the schedule).
- **It signals distrust of your own launch**, which is a real reputational cost some
  projects have declined to pay.

**5. Confidence.** **Medium.** Well-evidenced as a deployed pattern with a stated
rationale that matches Shekyl's situation almost exactly (unknown initial difficulty +
huge retargetable hardware base + a want for bounded bug blast radius). But it is an
*economics* rule sitting adjacent to a settled emission schedule, and it may well have
been considered and decided already. Phase 2 should check whether it was decided — and
if it was decided *against*, whether the reasoning survives the "zero hashrate at
genesis against the whole Monero miner base" framing.

---

## C11. Difficulty-window and block-weight bootstrapping at genesis must be explicitly defined

**1. The rule.** For every rule whose input is a window of the previous N blocks —
LWMA's difficulty window, the block-weight medians, MTP — the behaviour when fewer than
N blocks exist must be a **specified consensus rule**, not an implementation accident.
Specifically: what difficulty applies before the window fills, what the block-weight
median is when the long-term window is empty, and what MTP means at height 3.

**2. The threat it answers.** A first-mover at genesis exploits an underdetermined
bootstrap. Two concrete shapes: (a) the difficulty algorithm's behaviour over a partial
window is exploitable — the timespan/reverse-timestamp attacks of C3 are *strictly
easier* when the window is short, because a single block is a large fraction of it; (b)
the dynamic block-weight median is seeded from a handful of blocks, so an early miner
can inflate the median cheaply and enlarge the permitted block size far beyond the
intended growth curve. Actor: whoever mines block 1. Motive: cheap supply, or a
permanently inflated resource ceiling.

**3. The evidence.**

- **The "blockchain big bang" research on Monero's dynamic block weight** established
  that under the pre-2019 short-term-median-only algorithm, sustained load could grow
  the chain to **~30 TB in 36 hours** — an exponential resource blow-up on the scale of
  hours ([noncesense-research-lab](https://github.com/noncesense-research-lab/Blockchain_big_bang)).
  Monero's answer, from hard fork 10 (v0.15, Oct 2019), was the **long-term block
  weight**: a median over the last **100,000 blocks** damping the short-term median
  ([Monero Book, Block Weights](https://monero-book.cuprate.org/consensus_rules/blocks/weights.html)).
  **The relevant observation for a genesis chain is that a 100,000-block window takes
  months to fill, and the damping it provides does not exist until it does.**
- zawy #30's whole family of timespan/window attacks scales with `1/N` — the shorter the
  effective window, the cheaper the manipulation. At genesis, `N` is small by
  construction.
- **Honest caveat:** a chain deriving from post-2019 Monero very likely already
  *inherits* the long-term-weight rule. The candidate here is not "add long-term
  weights"; it is "the **bootstrap** case of every windowed rule is unspecified, and the
  bootstrap case is the only case that exists for the first months."

**4. The trade.**

- **Specifying the bootstrap means picking arbitrary seed values** — an initial
  difficulty, an initial weight median — and picking them wrong at genesis is
  unrecoverable. There is no way to defer this: *not* specifying it is also picking,
  just implicitly.
- **A conservative bootstrap (high initial difficulty, low initial weight ceiling)
  risks a stalled chain** at exactly the moment the chain has the least hashrate to
  recover with. A permissive one is the instamine of C10.
- **Low code cost, high decision cost.** The work is deciding, and it must happen before
  block 0.

**5. Confidence.** **Medium.** I am confident the *underlying windowed rules* exist and
are probably modern; I am confident the *bootstrap semantics* are the kind of thing that
lives as an implementation detail rather than a stated rule, which is precisely the
negative space this round is looking for. Lower priority than C1–C6, but it has a hard
deadline (genesis) that they do not.

---

## C12. Fork choice on cumulative work, with an explicit deterministic tie-break — and the coupling to C3 stated

**1. The rule.** Fork choice compares **cumulative proof of work**, never block count.
Ties in cumulative work are broken by a rule stated in consensus (not "first seen at
this node"), so that the tie-break is auditable. And the design must record that
cumulative work is only a meaningful metric *if* difficulty cannot be manipulated —
i.e. C12's soundness is conditional on C3.

**2. The threat it answers.** Two. (a) If any code path compares heights rather than
work — and mixed comparisons are a classic source of consensus bugs — an attacker
produces a long, low-difficulty branch (cheap, via C3's timestamp attacks) that wins on
count while losing on work. (b) Under first-seen tie-breaking, a well-connected
withholder wins ties disproportionately; the Qubic measurement found tie-break win rates
of **49% at ~35% hashrate (period 1)** and **60% at ~34% (period 3)** — a real,
measured, better-than-proportional advantage ([arXiv 2512.01437](https://arxiv.org/html/2512.01437)).

**3. The evidence.**

- The Qubic tie-break numbers above are the strongest measured evidence I found that
  first-seen tie-breaking is exploitable in production, on a CryptoNote chain, in 2025.
- **zawy #30, vector 10**, lists "chain work exploitation" as algorithm-dependent and
  affecting tip selection, and vector 1 (timespan limit) describes producing unlimited
  *blocks* within a window — the count-vs-work distinction made concrete.
- **This is where I record the Eyal–Sirer null** (§0.3): uniform random tie-breaking
  raises the selfish-mining threshold to ~25% in theory, and **no deployed chain shipped
  it**. The record shows chains reaching for freshness (C2) instead. I am therefore
  *not* proposing uniform tie-breaking; I am proposing that the tie-break be **stated
  and deterministic**, which is a weaker and better-evidenced claim. C2 is the real
  answer to the tie-break advantage.

**4. The trade.**

- **A deterministic tie-break (e.g. lowest block hash wins) is not free**: it is
  grindable — a miner can search for a low-hash block — and it can cause nodes to
  switch tips more often than first-seen, raising orphan rates. First-seen is
  cheap and mostly works; its failure is exactly the withholding case, which C2 also
  addresses. So there is a real argument that C12's tie-break half is **redundant given
  C2**, and should be dropped rather than stacked.
- **The work-not-length half has essentially no trade** and is table stakes; the value
  of listing it is as an *audit obligation* — "assert that no fork-choice or
  alt-chain-eviction path anywhere compares heights" — rather than as a new rule.

**5. Confidence.** **Medium-low** as a new rule (cumulative-difficulty fork choice is
near-universal in CryptoNote). **High** as an *audit item*, and high on the value of
recording the C3 coupling explicitly: a chain that reasons "we use cumulative work so
we're fine" while its timestamps are manipulable has a false sense of safety, and that
false sense is exactly the kind of thing that never appears as a missing line of code.

---

## C13. A bounded worst-case block verification cost

**1. The rule.** A consensus limit on the *verification work* a single block may impose
— not just its size or weight, but a bound on the total cost of PoW verification plus
proof/signature verification — such that no valid block can take pathologically long to
validate on the stated minimum device.

**2. The threat it answers.** An attacker crafts a maximally-expensive-to-verify block.
The immediate effect is a DoS on nodes; the *consensus* effect is worse and is why this
belongs here: a block that takes seconds or minutes to verify propagates slowly, which
manufactures exactly the propagation asymmetry that selfish mining (C2) exploits — and
the attacker, who does not need to verify their own block, gets a free head start on the
next one. Motive: amplify a withholding attack, or simply stall a minority chain whose
node population runs on small hardware.

**3. The evidence.**

- **The Great Consensus Cleanup lists "worst-case block validation time" as one of its
  four items**, proposing to limit the size of legacy transactions to bound signature
  operations; the rationale recorded in the thread is that validation "can be
  deliberately slowed through signature-heavy blocks" and that a bound provides
  "additional safety margin" ([bitcoindev thread](https://groups.google.com/g/bitcoindev/c/CAfm7D5ppjo)).
  That Bitcoin is *still* proposing this in 2024–25, sixteen years in, is the evidence
  that it is easy to leave out.
- **RandomX verification cost is already a live constraint in this exact design space.**
  tevador ruled out Fruitchain-style defences for Monero on the ground that "RandomX is
  too slow to verify": a block carrying 100 work shares would need **~1.5 s** of PoW
  verification alone ([research-lab#144](https://github.com/monero-project/research-lab/issues/144)).
  A chain that adds PQ signature verification and membership proofs on top of RandomX
  verification is stacking three expensive verifications per block, on a stated device
  floor of a Pi 4.
- **Coinspect's Bitcoin DoS work** demonstrates the general shape — crashing competing
  miners cheaply ([Coinspect](https://www.coinspect.com/blog/bitcoin-denial-of-service/)).
  I did not read this in depth; treat as pointer, not as grounded evidence.

**4. The trade.**

- **The bound must be measured on the floor device, not the developer's machine**, and
  it therefore constrains block capacity for everyone based on the slowest supported
  node. That is a permanent throughput ceiling set by a hardware choice.
- **It is hard to state as a clean consensus rule.** "Verification cost" is not a
  natural unit; it becomes a weighted count of operations, and the weights are a
  guess that ages badly as hardware and proof systems change. Getting the weights wrong
  is a consensus-visible mistake.
- **It may already be implied** by block weight limits plus per-transaction proof
  structure. The candidate is only interesting if the *worst case* — not the typical
  case — was ever computed.

**5. Confidence.** **Medium-low** on the gap. **Medium** on the value of the *question*:
"what is the slowest valid block, in seconds, on a Pi 4, and does that number make
selfish mining easier?" is a question with a number as its answer, and if that number
has never been computed then the rule's absence is real. This is the weakest candidate
in the document and is listed last deliberately.

---

## Appendix A — Things I looked at and deliberately did not propose

| Item | Why not |
|---|---|
| **Uniform random tie-breaking** (Eyal–Sirer, γ=½ → 25% threshold) | No deployment record found in any chain; raises orphan rate; C2 is the better-evidenced answer to the same threat. Recorded as a named null, §0.3. |
| **Merge-mining with a larger chain** | Raised repeatedly as a Monero post-Qubic option, but it is a PoW-structure change and RandomX v2 is ratified closed. Flagged, not proposed. |
| **PoW algorithm change / algorithm rotation** (Vertcoin's Lyra2REv3 response) | Same reason. Vertcoin changed algorithm after its first attack **and was attacked again**, which is itself worth knowing: algorithm change did not solve it. |
| **External anchoring (Komodo dPoW, VeriBlock PoP)** | Deployed and effective, but imports a permanent dependency on a foreign chain and an elected notary set — contradicts "must outlast the team." Discussed under C6 as the alternative family. |
| **DNS-sourced rolling checkpoints (Monero's `--enforce-dns-checkpointing`)** | The mechanism Monero reached for in Sep 2025, but it is opt-in, DNS-trusting (DNS incidents in 2019 and 2023 are cited in the thread as objections), and its own proposers call it "an emergency bandaid, not permanent." A worse version of C1. |
| **Consensus-encoded confirmation-depth guidance** | Named null, §0.3 — no chain shipped it. Folded into C8 as an argument for publishing `R` as a versioned constant. |
| **Difficulty-algorithm changes (RTT / real-time targeting)** | zawy #30 recommends real-time targeting as requirement 4, and it would help a chain with volatile hashrate. **But it is a change to the difficulty algorithm, and LWMA-1 is ratified closed.** I am recording it here rather than as a candidate so that phase 2 knows the recommendation exists and was set aside on policy grounds, not on merit. If the LWMA decision is ever reopened for an unrelated reason, RTT should be on the table. |

## Appendix B — Where the literature cuts against the stated posture

Three places, stated plainly because the brief asked for them.

1. **The measured Qubic campaign was not profitable, and never held sustained majority.**
   The posture says "51% capability is cheaply available." The best measurement of the
   most-cited recent attack found an average of **23.38%** hashrate, a peak of 28.33%
   during withholding periods, aggregates that "never reached 51%," and a **4.0% deficit
   against the honest-mining baseline** — the attacker lost money on block rewards
   ([arXiv 2512.01437](https://arxiv.org/html/2512.01437)). Qubic's own "51% takeover"
   announcement was marketing. This does **not** invalidate the posture — the attacker's
   payoff was reputational and token-price-driven, not block rewards, which is exactly
   the "externally incentivised" model the posture names — but it does mean the
   *quantitative* claim "51% is cheaply available" is not supported by the one case most
   often cited for it. Designing to it is defensible; asserting it as measured fact is not.

2. **The strongest depth-limit retrofit in the record was switched off.** ETC deactivated
   MESS in January 2024 because the hashrate circumstance changed. If Shekyl ships a
   depth limit without a written sunset criterion, it ships a rule that will one day be
   wrong and hard to remove ([ECIP-1110](https://ecips.ethereumclassic.org/ECIPs/ecip-1110)).

3. **The deepest reorg in the corpus was misclassified while it was happening — and
   the misclassification ran in the *reassuring* direction.** ETC's 3,693-block reorg
   on 1 Aug 2020 was first reported as an accident: a miner running old software after
   being offline ([CoinDesk, 1 Aug 2020](https://www.coindesk.com/markets/2020/08/01/ethereum-classic-suffers-reorganization-that-resembles-51-attack-amid-miner-complications)).
   It was subsequently established as a deliberate 51% attack — the attacker moved
   >807,000 ETC off OKEx between 29–31 July, mined a private shadow chain from block
   10,904,146, and published it on 1 Aug; Bitquery traced **$5.6M** double-spent, and
   OKEx's own incident report describes the shadow-chain sequence
   ([OKX incident report](https://www.okx.com/academy/en/okex-responds-to-ethereum-classic-51-attacks-reveals-its-hot-wallet-system-incident-report); see also [Coinbase's ETC double-spend post](https://www.coinbase.com/blog/coinbases-perspective-on-the-recent-ethereum-classic-etc-double-spend)).
   *This is my reconciliation of two conflicting contemporaneous reports, per §0.4.*

   The finding is not "deep reorgs are usually accidents." It is sharper and worse:
   **nobody could tell which it was at the time, and the first read was wrong.** Every
   rule in C1 and C6 must decide in seconds, on the evidence available in seconds, and
   that evidence pointed at "accident" for an event that was an attack. A rule tuned to
   spare accidents would have spared this attacker; a rule tuned to stop attackers will
   one day permanently split the network over a misconfigured miner. There is no
   parameterisation that escapes this, and any depth-limit proposal that does not name
   it is incomplete.

---

## Appendix C — Phase-2 carries routed from steering (2026-09-03)

Two items routed by shekyl-core-00 for phase 2 to land **when it edits the census** —
banked here because the census edit belongs in phase 2's authorized branch, not in a
side push. Both grounded at source in this session before banking (worktree lines
match steering's dev@a566a46 citations).

### C.1 Census §10 queue: R2 is DEFERRED (Rick, 2026-09-03)

The census's §10 queue currently lists R2 as next after R1; Rick has deferred R2
explicitly and with criteria, ruled from a fresh clone at dev `a566a46` via the
fee-ladder lane. The deferral must be visible **in the queue row itself** — the
criteria currently live only on the fee-ladder lane's local, unpushed branch, which a
census reader cannot reach. Text for §10's R2 row (adapt to the table's shape):

> **DEFERRED (Rick, 2026-09-03).** New terminal-emission findings from the fee-ladder
> round jump this queue. R2 resumes when **both**: (a) the terminal emission ruling
> **FL-R12′** is signed in `FEE_LADDER_DERIVATION.md` §8, and (b)
> `projected_already_generated` carries a red test at the exhaustion boundary.
> Conjunct (b) is **discharged** — `terminal_reward_legs_agree`, `#[ignore]`d,
> observed red (600000000 vs 599999999 at the first diverging block). Conjunct (a)
> is open.

Additionally: the R2 rows themselves (CEN-M3, F14b, G6b and the rest of the fee/
emission family) each get a pointer to the deferral, so a future round cannot
disposition a fee row while the governing ruling is pending in another lane.

### C.2 Gap-row candidate: two supply clamps encode opposite terminal policies

The finding that made R2 unrulable, per Rick's review of the fee-ladder round — and
a canonical instance of what a site-anchored census row cannot express: **each clamp
is individually correct; only their composition is contradictory.**

- `shekyl_advance_already_generated` (called at `src/cryptonote_core/blockchain.cpp:6410`,
  also `:2362` alt-path): saturates the running total at MONEY_SUPPLY. The comment
  block above `:6410` states the inherited **tail-forever** rationale in terms:
  "MONEY_SUPPLY yields a subsidy of 0 under the base formula and therefore the
  minimum subsidy >0 in the tail state."
- `shekyl_cap_reward_to_remaining_supply` (called at
  `src/cryptonote_basic/cryptonote_basic_impl.cpp:168`): caps a single block's reward
  at remaining headroom — **pays zero at exhaustion**.
- The `shekyl_ffi.h:333–338` doc comment names them "twins" (one stops the running
  total, one stops a single block) without registering that the twins encode
  **opposite terminal policies**: one exists so emission continues at the tail
  minimum forever; the other stops emission dead at the cap.

**The prose is the evidence, not a supporting note (steering-verified 2026-09-03) —
the gap row must QUOTE both passages,** because the code alone could be an accident
while the documentation proves nobody examined the composition:

> `shekyl_ffi.h:333–335`: "The emission-side **twin** of
> `shekyl_advance_already_generated`: that one stops the running total at the cap,
> this one stops a single block from exceeding what remains."

> `blockchain.cpp:6400–6403`: "the number of coins will eventually exceed
> MONEY_SUPPLY … cap already_generated_coins at MONEY_SUPPLY … MONEY_SUPPLY yields
> a subsidy of 0 under the base formula **and therefore the minimum subsidy >0 in
> the tail state.""

The header's "twin" actively asserts one mechanism distinguished only by scope;
the blockchain.cpp clause states tail-forever as a consequence, locally valid on
its own premise. Each comment is true about its own function and silent about the
other's policy — a reader holding both in mind could not have written either
sentence.

So "which side did the code take" was malformed — it took both. Grounded in this
session at the three sites above (grep + read, not recalled). Phase 2 should mint a
`gap` row for the composition contradiction; its resolution is exactly conjunct (a)
of the R2 deferral (FL-R12′), so the row should cite the deferral rather than
propose its own ruling.

**Methodology-preamble instruction (steering, 2026-09-03): this is the WORKED
EXAMPLE for phase 2's preamble, not an aside** — the purest instance of the C2-R0
premise: a site-anchored census carried both clamps as individually-correct rows,
each with a real `file:line`, each accurately described, and the defect exists only
in the relation between them. No sharper demonstration exists that a row-per-site
instrument cannot see a contradiction that has no site.
