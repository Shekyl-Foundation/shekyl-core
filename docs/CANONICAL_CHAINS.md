# Canonical test chains and the chain forge — Round 0 (2026-11-13)

**Rick, 2026-11-12:** build one or two complete, accurate chains for KAT testing and validation, at difficulty 1, so every lane tests against a REAL chain; build the apparatus that creates them, which also serves stress testing. Check how many lanes need it and capture every aspect they need (epoch switch, transactions, bond posts, …).

**Ground:** `dev` at `8b79e82f4`. Census by a read of the whole tree (tests, benches, harnesses, `scripts/bench`, `FOLLOWUPS.md`, design docs).

## 1. The census in one paragraph

About **45 consumers** build or replay realistic chains, and **five** committed chains exist (`chain-ingest/tests/vectors/`: spend-1in-2out 82 blocks, bond-post 109, limit-full 215, median-full 216, spend-depth3 762; 5.4 MB together, all fixed difficulty 1, format v4, captured from a live daemon by `regtest_e2e.rs` generators). **None of them crosses a settlement epoch** (production `settlement_epoch_blocks` = 10,000). So every test that needs a closed shard, a settled epoch, a claim, a slash or a discard **rebuilds that history itself**: about 13 nightly scenario tests and 2 nightly-slow daemon walks each fill shard 0 with ~289 real proofs, for minutes each, sharing nothing. And a long list of properties has **no realistic witness at all**:

| Gap | Where it shows |
| --- | --- |
| No chain crosses an epoch: ServeCredit, RMarket, SigmaWork, Budget, LastSlashEpoch unwitnessed | `archival_sufficiency_tests.rs:96–121, 280–323` (one test returns early "UNWITNESSED"); FOLLOWUPS:171 |
| No chain slashes, claims, releases, reinstates, or carries compact joins or serve credits | ARW-Q18; `archival_corpus_tests.rs:180–193` |
| RMarket/SigmaWork settlement arithmetic unexercised by any chain ("captured chains are too short") | `ARCHIVAL_SETTLEMENT_WRITER.md:1093–1100, 1997–2001` |
| No chain carries a reorg or alt block | `DRS_E5_POOL_ALT_PRUNE.md:380–385` (E5-10) |
| LWMA beyond its first window never replayed | `DRS_E2_REPLAY_DRIVER.md:901` |
| Burn oracle: 3 non-zero heights of 2,408; pool half zero until ~2,600 blocks | FOLLOWUPS ~357; `regtest_e2e.rs:4280` |
| ~20 store tests use **padded serve credits**; every synthetic leaf identical | FOLLOWUPS:190, 194 |
| Serve-credit countersignature is a **fake** `0x5c×64`; no Rust countersigner | `harness-spender/src/persona.rs:144–163` |
| No attestation witness in any capture | FOLLOWUPS:363 |
| No multisig (scheme-2) spend builder anywhere | census |
| Emission-claim daemon e2e is DECIDED_DARK; bench row blocked (#1360) | `regtest_e2e.rs:4303` |
| PB-D2/D3 catch-up and the IBD/crash/power-loss harnesses run on **coinbase-only** chains | `drs_catchup.py:21–25`; BA-I69; FOLLOWUPS:1375 |
| `cs2-long-run` has never run | no runner |

The lanes behind those consumers: DRS (store, prune, pop), DRS-SB (below horizon), SO-D12 (settlement writer, bundles), archival/staking (joins, credits, claims, slashes, release/unstake), chain-sync/P2P (loopback, long run), curve tree (depth, trim), wallet (scan, open edge), economics (burn oracle, pool, emission), the daemon budget (PB-D1/D2/D3, catch-up, crash), and the benches (#1360's emission-claim and settled-epoch rows). That is most of the project.

## 2. What to build: two chains, one forge

### Chain L — **Lifecycle** (correctness; every feature, levered schedule)

The chain every correctness test reads from. Small enough to regenerate in about an hour on a workstation, so it can follow consensus changes.

- **Schedule:** the regtest levered archival schedule (the scenario driver's "settled" derivation, SEB ~300, cap as the driver sets), fixed difficulty 1.
- **Length:** enough for **at least four settled epochs plus the body horizon** (so a discard has happened and a later epoch settles on discarded bodies), and past the **RandomX seed boundary (2,112)**: about 3,000 blocks.
- **Content, each at least once, each findable by height in the manifest:**
  - spends: 1-in/2-out, 8-in (`MAX_INPUTS`), 1-in/16-out, spends to watched wallets (so wallet scans have real outputs), a block at the consensus weight bound, a block filled to the median;
  - curve tree to depth 3;
  - joins (complete tree, shard set, compact), **real** serve credits with a **real** countersignature, bundles and support bundles through the staged door, epoch close and settlement with non-zero RMarket/SigmaWork/Budget, emission claims, a missed-epoch slash, reinstate, release, unstake, collect, retire;
  - a shard discarded below the horizon, then a spend whose shard was discarded;
  - **reorgs as recorded alt branches**: one shallow, one at the cap, one across an epoch boundary and one across a prune boundary, each with spends that return to the pool;
  - multisig scheme-2 spends (once the builder exists);
  - attestation witnesses (once they exist).
- **Deterministic:** every key, persona, wallet seed, timestamp and nonce derives from one seed; regenerating at the same commit reproduces the chain **byte for byte**. That makes the chain itself a KAT: regenerate at HEAD, and the first differing block names the consensus change.

### Chain P — **Production schedule under load** (performance and stress)

- **Schedule:** the production archival parameters (10,000-block epoch), fixed difficulty 1.
- **Load:** the PB design load (30 tx/block, ruled) for the PB-D2 window of **5,040 blocks**, plus a **stress segment** at 4× (PB-D3).
- **Purpose:** the daemon budget's catch-up (D2/D3), IBD, crash and power-loss runs (S1/S2) on a real chain instead of a coinbase-only one; long-run sync; floor sessions.
- **Not** a correctness oracle: it carries no archival lifecycle (its epoch never closes inside 5,040 blocks), only realistic load.
- **Size:** ~150,000 spends at ~30 KB is several GB. It is **not committed**; it is a pinned artifact (§4).

LWMA: both chains are fixed difficulty 1 as Rick ruled. LWMA past its first window gets a **third, short chain** (a few hundred blocks under live LWMA with spaced timestamps), because difficulty dynamics and fixed difficulty are mutually exclusive in one chain.

## 3. The forge

One Rust tool, `shekyl-chain-forge`, built on what already works:

- **Engine:** the scenario driver in process (production stack: template → `form` → validate → connect), the harness spender for transactions, `emission_assembly` for claims. No live daemon in the loop: faster, deterministic, and no RPC lever needed.
- **Script:** a declarative plan (TOML) of events by height or by phase: "fill shard to close", "join complete tree", "serve credits for N personas for epoch E", "claim", "slash persona X", "fork at h depth d with these spends", "load profile 30 tx/block for 5,040 blocks". Chain L and Chain P are two plans; a lane needing a new feature adds an event to the plan, not a new bespoke harness.
- **Output:** the existing corpus/trace pair, **extended to format v5** with recorded alt branches, plus a manifest that indexes every event by height ("first settled epoch", "first claim", "discard of shard 0", …), so a consumer asks for "the chain up to the first claim" instead of a magic height.
- **Store snapshots, not committed:** a CI job replays the committed corpus once through full verification into a store and caches the store keyed on (corpus hash, store schema version). Tests and benches that need "the state at the first settled epoch" open a copy of the cached snapshot instead of replaying 1,000 blocks. That is the emission-claim bench row's setup, and it ends every nightly test's private shard refill. The snapshot is always rebuilt from the corpus by the production connect path; nothing trusts an unverified store.
- **Stress mode:** the same plans drive a live seed node for IBD and catch-up, and the forge's load profiles (max-weight blocks, slash storms, withheld blocks) become the PB-D1 adversarial set.

### Gaps the forge must close first (each is its own small PR)

1. **A real Rust serve-credit countersigner** in the harness spender (replaces `0x5c×64`).
2. **Corpus format v5** with alt branches and switches (E5-10).
3. **Scheme-2 (multisig) spend builder** — owned by the multisig lane; Chain L gets the event when it lands.
4. **Attestation witness** — when its lane lands it.
5. **Determinism audit** of the driver and spender: no wall clock, no OS randomness, no hash-map iteration order in anything that reaches a block.

## 4. Where the chains live

| | Size (est.) | Storage | Regenerated |
| --- | --- | --- | --- |
| Chain L corpus + trace + manifest | ~3,000 blocks, ~2,000 tx: **~60–80 MB** | committed if ≤ 50 MB compressed; otherwise a release asset pinned by SHA-256 in the repo and fetched by a script | on any consensus-affecting change, by a PR that names the first differing block |
| Chain P corpus | several GB | release asset, pinned by hash | at release cuts |
| LWMA chain | small | committed | as Chain L |
| Store snapshots | — | CI cache only | from the corpus, on cache miss |

## 5. Migration

- The five existing corpora are subsumed by Chain L's events and retired once every consumer reads Chain L (the replay tests, chain-sync loopback, `h19_cost`, `corpus_census`).
- The ~15 nightly tests that refill shards switch to Chain L snapshots; the padded-credit store tests switch to real credits.
- The `regtest_e2e.rs` capture generators stop being corpus generators; they keep their role as live-daemon end-to-end tests.
- `archival_sufficiency_tests`' unwitnessed families become witnessed; ARW-Q18's "unwitnessed by ruling" is revisited.

## 6. Decisions for Rick

1. **Two chains plus a short LWMA chain** (L for correctness on the levered schedule, P for load on the production schedule), or one chain.
2. **Byte-for-byte deterministic regeneration**, making Chain L a KAT whose first differing block names a consensus change. Recommended.
3. **Storage:** Chain L committed if it compresses to ≤ 50 MB, else a hash-pinned release asset; Chain P always a release asset.
4. **Order:** the forge and Chain L first (it unblocks the most: SO-D12, DRS-SB, the archival rows, the emission-claim bench), with gaps 1, 2 and 5 inside that round; Chain P second, with the daemon budget lane.
5. **Owner:** a new lane (the chain forge), with each consuming lane migrating its own tests.