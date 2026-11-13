# The chain forge and the canonical test chains

**Status:** OPEN — Round 0 (`CF-0`). `CF-R1`…`CF-R15` RULED by Rick 2026-11-12 and 2026-11-13 (§1; `CF-R6`…`CF-R9` and `CF-R13` rule `CF-Q1`…`CF-Q5`, `CF-R11` the hosting, `CF-R12` the seedable-RNG gate, `CF-R14` the hosting repository's setup, `CF-R15` the harness identity's end and the public seed, §13). `CF-F1`…`CF-F14` recorded at `4b867a4f8` (§2). No question open. `CF-0` merged (#1363); `CF-1a` BUILT (as of 2026-11-13, #1370); no forge crate yet.
**Family:** **`CF-`**, registered in `IMPLEMENTATION_INDEX.md` §2 at birth (rule 94): `CF-0`…`CF-6` the increments (the brief's F0…F6; `CF-1` is split as `CF-1a`…`CF-1c`, `CF-R10`), `CF-R` rulings, `CF-Q` questions, `CF-F` findings, `CF-E` catalogue events.
**Ground:** `dev` at `4b867a4f8` (at or after `8b79e82f4`, as the lane brief asks). Every `path:N` below is read at that commit.
**Owner:** the chain forge lane. It owns `shekyl-chain-forge`, the canonical chains and their regeneration. Each consuming lane migrates its own tests (`CF-R5`); §12 tracks them.
**Related:** `DRS_E2_REPLAY_DRIVER.md` (the corpus and trace), `DRS_E5_POOL_ALT_PRUNE.md` (`E5-10`), `ARCHIVAL_SETTLEMENT_WRITER.md`, `DAEMON_REDB_STORE.md` §1.3a (the `PB-` budget) and §12.1, `NETWORK_IDENTITY.md` (`NI-R4`, `NI-R6`, `NI-R10`), `CHAIN_RULES_SLICE_6.md` §5.3 (the scenario driver), rules [`50-testing`](../../.cursor/rules/50-testing.mdc), [`71-network-uniformity`](../../.cursor/rules/71-network-uniformity.mdc), [`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc).

**What this is.** Rick, 2026-11-12: build complete, accurate chains for KAT testing and validation, at difficulty 1, so every lane tests against a real chain, and build the apparatus that creates them, which also serves stress testing. This document is the Round 0 design: the census of what lanes need (§0, §3), the chains that carry it (§4), how a chain is forged so that it regenerates byte for byte without making production code seedable (§5, §6), the artifact formats (§7, §8), the regeneration and storage policy (§9, §10), the forge itself (§11) and the increments (§12).

This file began as Rick's Round 0 draft (`docs/CANONICAL_CHAINS.md`, `4b867a4f8`) and was moved here by `CF-0`. The census in §0 is his, corrected where the tree disagreed (§0.2).

---

## 0. The census

### 0.1 In one paragraph

About **45 groups of consumers** build or replay realistic chains (counted per test it is several hundred: about 60 tests read the committed corpora, 24 nightly in-process tests build real-proof chains, about 120 PR-lane driver tests build short ones; §12.2 lists them by group). **Five** committed chains exist (`rust/shekyl-chain-ingest/tests/vectors/`: `spend-1in-2out` 82 blocks, `bond-post` 109, `limit-full` 215, `median-full` 216, `spend-depth3` 762; 1,384 blocks and 5.1 MB together, all fixed difficulty 1, the production schedule, captured from a live regtest daemon by `regtest_e2e.rs`'s generators). **None of them crosses a settlement epoch** (production `settlement_epoch_blocks` = 10,000). So every test that needs a closed shard, a settled epoch, a claim, a slash or a discard **rebuilds that history itself**: 13 nightly tests (12 in-process scenario fills listed in `scripts/ci/ignored_set_chain_ingest.sh` and `shekyl-chain-store`'s `prune_tests.rs:825`) and 2 nightly-slow daemon walks each fill a shard with real proofs (about 227 a shard in-process, about 289 through the daemon), for minutes each, sharing nothing. And a long list of properties has **no realistic witness at all** (§0.2).

### 0.2 The gaps, verified at `4b867a4f8`

| Gap | Where it shows |
| --- | --- |
| No chain crosses an epoch: ServeCredit, RMarket, SigmaWork, Budget and the LastSlashEpoch watermark are unwitnessed | `archival_sufficiency_tests.rs:96–121`; `:280–323` returns early "UNWITNESSED" at `:319–322`; `docs/FOLLOWUPS.md:171` |
| No chain slashes, claims, releases, reinstates, or carries compact joins or serve credits | ARW-Q18 (`docs/completed/DRS_E4_ARCHIVAL_WRITER.md:26`); `archival_corpus_tests.rs:180–193` |
| The RMarket and SigmaWork settlement arithmetic is unexercised by any chain ("captured chains are too short") | `ARCHIVAL_SETTLEMENT_WRITER.md:1093–1100`, `:1997–2001` |
| No chain carries a reorg or an alt block | `DRS_E5_POOL_ALT_PRUNE.md:380–385` (`E5-10`); no FOLLOWUPS row |
| LWMA beyond its first window is mined nightly but never **replayed** | `DRS_E2_REPLAY_DRIVER.md` §7 item 8; mined by `miner_tests.rs:425` |
| The burn oracle has three non-zero heights in the captured chains, and the pool half is zero until about 2,600 blocks of the young curve | `docs/FOLLOWUPS.md:355`; `regtest_e2e.rs:4289–4295` |
| 18 store tests in `prune_tests.rs` run on **padded serve credits**, and synthetic leaves are identical | `docs/FOLLOWUPS.md:190`, `:194`; `shekyl-chain-store/src/store/prune_tests.rs` (`sized_credit`) |
| The harness persona's serve-credit vin carries a **marker** countersignature `[0x5c; 64]`; no Rust code makes the vin's real one, and no landed rule verifies it | `shekyl-harness-spender/src/persona.rs:144–164`; `docs/FOLLOWUPS.md:186` (CEN-J8–J10 have no Rust rule) |
| No capture carries an attestation witness | `docs/FOLLOWUPS.md:363` |
| No scheme-2 (multisig) spend builder in the harness spender or the driver (`shekyl-fcmp/tests/frost_spend.rs` builds one at the crypto level) | — |
| The emission-claim daemon walk is DECIDED_DARK, and #1360's emission-claim bench row needs a store holding a settled epoch | `regtest_e2e.rs:4303`; `scripts/ci/run_live_daemon_gates.sh:315–322`; #1360's body |
| `PB-D2`/`PB-D3` catch-up **refuses** a coinbase-only chain and so cannot run; the IBD (`drs_bench.py`, BA-I69), crash and power-loss harnesses run coinbase-only; the open-edge bench has no realistic-weight corpus | `scripts/bench/drs_catchup.py:18–26`; `BENCHMARK_ALIGNMENT.md:248`; `docs/FOLLOWUPS.md:1375` |
| `cs2-long-run` has never run | `.github/workflows/cs2-long-run.yml` header |

Corrections to Round 0's citations (`CF-F13`): the burn row is FOLLOWUPS `:355`, not `~357`, and its "six chains, 2,408 heights" is stale (five chains, 1,384 blocks); the burn sentence is `regtest_e2e.rs:4289–4295`, not `:4280`; `drs_catchup.py` refuses a coinbase-only chain rather than running on one, and FOLLOWUPS `:1375` is the open-edge bench, not IBD/crash/power-loss; a scheme-2 spend is built at the crypto level (`shekyl-fcmp/tests/frost_spend.rs`); the in-process fill is about 227 proofs a shard (289 is the daemon walk's).

### 0.3 The lanes behind those consumers

DRS (store, prune, pop), DRS-SB (below horizon), SO-D12 (settlement writer, bundles), archival and staking (joins, credits, claims, slashes, release, unstake), chain sync and P2P (loopback, long run), the curve tree (depth, trim), the wallet (scan, open edge), economics (burn oracle, pool, emission), the daemon budget (`PB-D1`/`D2`/`D3`, catch-up, crash) and the benches (#1360's emission-claim and settled-epoch rows). §12's table names each consumer, its lane and its target.

---

## 1. Rulings — RULED 2026-11-12 (Rick)

- **CF-R1 — RULED 2026-11-12: as many chains as the testing needs require, no fewer.** Needs that do not fit one chain are not shoehorned into it. Chain L (lifecycle, levered schedule), Chain P (production schedule under load) and a short LWMA chain are the starting set; §3's catalogue decides whether more are needed, and §4 records that decision.
- **CF-R2 — RULED 2026-11-12: byte-for-byte deterministic regeneration.** Each chain is a KAT. Regenerating at the same commit reproduces it exactly; at a new commit, the first differing block names the consensus change.
- **CF-R3 — RULED 2026-11-12: commit the chains if possible.** A hash-pinned release asset only when a chain is too large (Chain P will be). The line is `CF-R6` (5 MB, against the history cost `CF-F4` measured); the hosting is `CF-R11` (digest-pinned OCI artifacts on GHCR, not release assets).
- **CF-R4 — RULED 2026-11-12: order.** The forge and Chain L first; Chain P second, with the daemon budget lane.
- **CF-R5 — RULED 2026-11-12: a dedicated lane** owns the forge and the chains. Each consuming lane migrates its own tests.
- **CF-R6 — RULED 2026-11-12 (rules `CF-Q1`): the storage line.** Chain bytes up to 5 MB are committed. Above that, the manifest, the block-hash list (`blocks.txt`) and the trace are committed, and the bytes are pinned by SHA-256 (hosted as digest-pinned OCI artifacts on GHCR, `CF-R11`). **The hosted copy is a cache:** deterministic regeneration at the pinned commit is the source of truth. The five old corpora move to this scheme when they are next regenerated (§10.3).
- **CF-R7 — RULED 2026-11-12 (rules `CF-Q2`): read both corpus layouts until the last old corpus is gone,** then delete the old reader. No live-daemon re-capture (§7.1).
- **CF-R8 — RULED 2026-11-12 (rules `CF-Q3`): the forge's runnable is a cargo example. CI must build the examples** (§11.1).
- **CF-R9 — RULED 2026-11-12 (rules `CF-Q4`): the no-injectable-RNG line sits at Shekyl's signing and proving entry points** (§5.3). Added to `CF-1b`: `prove_with_rng` becomes crate-private behind a test-only `seeded-rng` feature, which `shekyl-verify-cost` enables; and a gate refuses any seedable-RNG construction (`from_seed`, `seed_from_u64` and similar) in production code outside test-only features (§5.5).
- **CF-R10 — RULED 2026-11-12: `CF-1` splits in three, and Chain B is accepted conditionally.** `CF-1a` chain identity (regtest genesis, regtest network id, personas derived under regtest's name); `CF-1b` the RNG line (`CF-R9`, the forwarded-feature gate fix `CF-F5`, and `shekyl-crypto-pq` under the gate through F-7); `CF-1c` the forge skeleton and the determinism CI check (§12.1). Chain B is accepted, conditional on `CF-1c`. If the bundle producer depends on anything but chain state, `CF-1c` says whether that is by design: if it is, B's regeneration check compares state digests rather than bytes; if it is not, it is filed with SO-D12 (§4). §4 records how the state comparison is met while B stays hosted as a cache of its regeneration (review of `CF-0`, 2026-11-13): B's bytes are forged from its recorded inputs, and the comparison holds the live producer's run to B on a named projection of settlement outcome.
- **CF-R11 — RULED 2026-11-12 (the hosting of `CF-R6`'s pinned bytes): OCI artifacts on GHCR, pushed and pulled with `oras`, pinned by digest.** One artifact per chain version at `ghcr.io/shekyl-foundation/test-chains/<chain>` (for example `…/test-chains/chain-l`), in a public package linked to a new repository, `Shekyl-Foundation/shekyl-test-chains`, which holds the forge plans, manifests, per-block hash lists and release notes. Layers carry their own media types; shekyl-core commits a pin file; the fetch script pulls by digest and re-checks every layer; only a protected workflow in `shekyl-test-chains`, approved by Rick, publishes; chains of 5 MB or less stay committed in shekyl-core. The artifacts are a cache: deterministic regeneration at the pinned commit is the source of truth, so a deleted package is rebuilt, never lost. A nightly check pulls every pinned digest (§9, §10.4).
- **CF-R12 — RULED 2026-11-12 (answers §5.5's reading of `CF-R9`): the seedable-RNG gate allows listed sites, never groups.** Each allowed site is listed by path and function, with its group and one line on where its seed comes from; naming a group allows nothing on its own. The allowed seed sources are these four and no others: **G0** a seed drawn from `OsRng` on the spot (`frost_sal.rs`'s `algorithm()` is one; such sites are listed anyway, so the gate never has to guess); **G1** the output of a key-derivation function over a secret key or seed; **G2** verifier batch weights taken from a domain-separated transcript, weights only, never a value that is published or signed; **G3** multisig values that every participant must derive identically, from a transcript that already binds every participant's commitments. **Always refused:** a constant seed, a seed the caller chooses, or a seed built from public data alone, at any signing or proving nonce; a fixed seed is available only through the test-only `seeded-rng` feature. **No grandfathering:** at `CF-1b` every current hit is listed with its justification or changed; a later site needs a reviewed change to the list; a file move drops the site's listing, which sends it back to review on purpose. **The SAL multisig** (`sal/multisig.rs`, `sign_share`) is allowed under G3: α, β, δ, μ, r_z, r_p and r_r_p cover parameters that are not secret within the signing group, as the upstream FCMP++ SAL design has it; only `y` is the threshold secret, and its nonce comes from FROST's hedged preprocess step. Two conditions, both in `CF-1b`: (a) a test that fails if the `y` nonce ever comes from the `deterministic_nonces` stream; (b) confirm in code, and record the line, that the transcript binds every preprocess commitment before `rng_seed` is called, which rules out reusing derived values across signing sessions (§5.5).
- **CF-R13 — RULED 2026-11-12 (rules `CF-Q5`): which repository holds what.** shekyl-core keeps each chain's plan and `blocks.txt`. `shekyl-test-chains` keeps the published manifests and release notes. The chain, its trace and its manifest go to GHCR as layers pinned by digest; the digest in shekyl-core is the source of truth, and a mismatch fails (§10.3, §10.4).
- **CF-R14 — RULED 2026-11-12: the `shekyl-test-chains` setup is accepted, and the package stays private until `CF-4`.** Making the package public cannot be undone, so it happens after the first artifact has been reviewed, and only on Rick's explicit approval. Rick checks the organization's public-package setting by hand before `CF-4` (§10.4).
- **CF-R15 — RULED 2026-11-13 (on `CF-1a`): two identities side by side for now, and the old one ends in `CF-5`.** `CF-1a` adds a regtest mode alongside the existing harness id, and §6 governs. The harness id (`HARNESS_NETWORK_ID`, the id the chains that mine their own genesis sign under) is test-only and is deleted in `CF-5`, so a later revival fails review instead of passing quietly; where the test-only feature gate can hold it, it does. Lock 4 is cited only by path and function to a test of the transport prefix, with lock 1–3's positive-control pattern. **The harness seed is public and regtest-only:** anyone who restores it can spend the regtest miner's coinbases, which is intended, and its addresses are refused on mainnet and testnet because their prefixes do not match, a refusal a test holds (§6).

The lane brief also fixes three security constraints. They are not open to design here; §5 and §6 show how each is met:

1. **Determinism is test-only.** The seeded randomness lives behind test-only features that `scripts/ci/check_test_only_features.py` polices. The production prover and signers keep OS randomness, with no injectable RNG in their public API.
2. **Chains are regtest-identity only.** Every forged block carries the regtest network identity; a forged chain can never validate under testnet or mainnet rules, and a test asserts it.
3. **Nothing trusts a store it did not verify.** Snapshots are built from the committed corpus by the production connect path with full verification.

---

## 2. Findings at `4b867a4f8`

- **CF-F1 — the scenario driver mines its own genesis and signs under the harness id, not regtest's.** `Scenario`'s rules are `RULES.unpinned()` (`rust/shekyl-chain-ingest/src/scenario.rs:144–152`) and the levered schedules are `ChainRules::harness_regtest`, which is `unpinned()` too (`schedule.rs:128–138`), so block 0 is held to nothing (`GenesisPin::NONE`). Every spend signs under `Spender::NETWORK_ID = HARNESS_NETWORK_ID` (`shekyl-harness-spender/src/spender.rs:102`), the all-zero id no network row carries (`shekyl-network/src/lib.rs:600–605`). Personas derive under `Network::Mainnet`'s name (`shekyl-harness-spender/src/persona.rs:69`). A chain forged on today's driver therefore replays under no network's rules, which is exactly what the brief's identity constraint (§1, security constraint 2) forbids. **Disposition:** §6 — the forge runs pinned to regtest's table genesis and signs under regtest's id; `CF-1a` builds it.
- **CF-F2 — the driver is test-only by construction, and the forge has to reach it without shipping it.** `scenario` is `pub(crate)` under `cfg(all(test, feature = "pipeline"))` (`shekyl-chain-ingest/src/lib.rs:51–56`, the module list at `:203`), on purpose: "a driver that shipped would be a second producer". The harness spender is reached from `[dev-dependencies]` edges only (`shekyl-chain-store/Cargo.toml:86`, `shekyl-chain-ingest/Cargo.toml:219`). A forge *binary* that depended on the driver through a normal edge would enable a TEST_ONLY feature on a normal edge, which the test-only gate refuses (limb 1). **Disposition:** §11 — the forge's runnable is a test-kind target, so every edge into the driver and the seed seams is a dev edge.
- **CF-F3 — two version numbers, and the brief's "v4 → v5" counts the manifest's.** The corpus's binary layout is `CORPUS_FORMAT_VERSION = 3` (`corpus.rs:106`: v1 untagged, v2 `rewind`, v3 `inject`); the capture manifest is `"format_version": 4` (`shekyl-engine-core/src/engine/regtest_e2e.rs:5831`). Alt branches change the binary layout, so `CF-3` moves the layout **3 → 4** and the manifest **4 → 5** (the event index). `corpus.rs`'s policy is that the reader refuses every other layout ("rebuild the artifact, never migrate it", `corpus.rs:22–26`), which the brief's "the replay tests read v4 and v5" contradicts for the migration window. RULED (`CF-R7`): read both until the last old corpus is gone, then delete the old reader.
- **CF-F4 — the chains are incompressible, so their cost is history, not checkout.** Measured on the five committed corpora at `4b867a4f8`: `zstd -19` saves 2.1–4.7 % and `xz -9e` 1.3–4.0 % (§10.1); ML-KEM ciphertexts and proofs are high-entropy. The five corpora are 5.1 MB checked out, and they have been re-captured about 20 times since 2026-09-15 (every consensus change that moved genesis, signing or a rule they cross: `git log -- rust/shekyl-chain-ingest/tests/vectors`). Their blobs now hold **96 MB on disk of the repository's 424 MB pack**: git cannot delta one regeneration against the last. **Disposition:** §10 prices the line as size × regenerations; `CF-Q1`.
- **CF-F5 — the test-only gate classifies a forwarded feature by the last edge listed.** `enablements()` maps each dependency alias to one edge (`scripts/ci/check_test_only_features.py:620–624`), so a crate that has both a normal and a dev edge to the same owner forwards over whichever its manifest lists last. Live instance: `shekyl-chain-ingest/harness` forwards `shekyl-chain-rules/harness`, and chain-ingest has both edges to chain-rules; the gate records the forward as `dev` (checked on `cargo metadata` at the pin). Cargo activates it on the normal edge too. It is safe today only because the forwarder (`shekyl-chain-ingest/harness`) is itself TEST_ONLY. A forward from an *ordinary* feature over such a pair would pass the gate and ship. The forge's seed seams forward through exactly this kind of crate (§5.3). **No live instance at the pin:** the workspace has five dual-edge forwards, and the two whose target is TEST_ONLY come from forwarders that are TEST_ONLY themselves (`shekyl-chain-ingest/harness`, `shekyl-mempool/pool-commit-fault`); checked over `cargo metadata` at `4b867a4f8`. **Disposition:** fixed in `CF-1b` (§5.4, `CF-R10`), the change that writes the first forwards the hole would admit (§5.3's seams). Every edge of the alias becomes an enablement, and a forward from a feature that is itself TEST_ONLY is governed by that feature's own row.
- **CF-F6 — the harness persona's serve-credit countersignature is a marker.** `Persona::serve_credit_vin` writes `ed25519_countersignature: [0x5c; 64]` (`persona.rs:144–164`); its doc says no Rust countersigner exists and no landed rule verifies it (CEN-J8–J10 pending, `docs/FOLLOWUPS.md:186`). The vin's field is the Ed25519 leg of a hybrid countersignature over `ArchivalServeCreditResponse::signature_preimage`, whose ML-DSA-65 leg (3,309 bytes) rides the pruned half (`shekyl-archival-retention/src/wire.rs@4b867a4f8:40–64`, `:120–134`). A Rust signer of a related object does exist: `shekyl-p-host`'s pass signer (`signer.rs`, run nightly by `bundle_producer_gate_tests.rs:160–166`) signs SF-D8's 113-byte transcript with the identity key's hybrid scheme (`shekyl-p-serve/src/countersign.rs:249–251`). Whether that transcript and the vin's preimage are one object is not established here. **Disposition:** `CF-2`, as the brief words it: a real serve-credit countersigner built to the serve-credit spec, with the verifier accepting it and refusing a tampered one. Its first question is whether the pass signer already is that countersigner (reuse it) or signs a different object (build to the spec); CEN-J10's owner (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §8.0) is consulted on which preimage the vin carries.
- **CF-F7 — nine sources of randomness reach a forged chain's bytes, all inside the production prover and signers or the witness ring, and none of their Shekyl-owned entry points takes a seed** (§5.2, S1–S9). Everything else on the path is already deterministic: the clock, the nonce, every key, every output's derivation, input and list order. **Disposition:** §5.3's seams, built in `CF-1b`; routed through the plan's seed in `CF-1c`.
- **CF-F8 — the archival schedules conflict, so one lifecycle chain cannot carry every archival event.** The *settled* schedule (`settled_epoch_blocks()`, derived ≈ 300 blocks, `scenario_shard.rs:80–125`) is where admitted draws settle every pair; it is wrong for the bundle producer ("No producer test belongs on this schedule": `W₂ = SEB/20` = 15 blocks sits below the producer's `FILING_MARGIN` of 30, `scenario_shard.rs:110–117`). The *levered* 20-block epoch (`EPOCH_BLOCKS`, `scenario_shard.rs:48–53`) is where a slash fits in a few hundred blocks; the producer's gate runs on "its own longer epoch". **Disposition:** §4 splits on the schedule.
- **CF-F9 — Chain L is smaller than Round 0 estimated.** A shard is `W = 3,000,000` bytes of archival good (`config/consensus_constants.json`, `archival_shard_length_bytes`), and one driven 1-in/2-out spend is about 13.2 KB on the wire (`limit-full`: 50 transactions, 661,750 bytes); a coinbase-only block is about 1.5 KB (`spend-depth3`: 762 blocks, 1,161,496 bytes, one 20 KB spend). §10.1 puts Chain L at **15–25 MB**, not 60–80 MB. The size line is still crossed by history (`CF-F4`).
- **CF-F10 — some archival state reaches today's chains beside the blocks, through regtest levers.** `IssueDraws` (`chain_drive.rs:168`, `:618`) and the serve-credit `inject` (`corpus.rs:52–70`) write archival rows no block carries; both are regtest-permitted (`NI-R6`). A replay reproduces them only if the corpus records them. **Disposition:** §7.3 — a forged chain is block-derived wherever a production path exists; a lever write is a corpus record and a manifest row, never a side effect.
- **CF-F11 — the corpora were re-captured under three consensus changes in three days** (2026-11-03 `NI-Q8`, 2026-11-04 the derivation salt, 2026-11-05 the signing envelope; `DAEMON_REDB_STORE.md` §12.1, the E2 row). Each needed a live daemon built at the head, a regeneration decision and a capture run per chain. That cadence is what `CF-R2`'s deterministic regeneration has to absorb at a lower cost.
- **CF-F12 — `shekyl-fcmp::proof::prove_with_rng` is a public prover entry point that takes its caller's RNG** (`shekyl-fcmp/src/proof.rs:519–527`). It exists for `shekyl-verify-cost`'s drift fixture (`relay.rs:331`, a normal edge). The brief's constraint is that no production prover's public API takes an injectable RNG. **Disposition:** `CF-1b` (`CF-R9`): crate-private behind a test-only `seeded-rng` feature that `shekyl-verify-cost` enables (§5.3).
- **CF-F13 — five of Round 0's citations were off** (§0.2's closing paragraph). Corrected in place by `CF-0`.
- **CF-F14 — production code already constructs seeded RNGs, deliberately, in three classes** (`CF-R9`'s gate, read at `4b867a4f8`). (1) **Key derivation from a secret seed:** account and persona keys (`shekyl-crypto-pq/src/account.rs`, `archival_p.rs`, `derivation.rs`, `seeded_rng.rs`, the KEM seeds in `output.rs`), the wallet envelope (`wallet_envelope.rs`), the onion key (`shekyl-onion-key`) and the Noise ML-KEM key (`shekyl-p2p-transport/src/noise.rs:162`). (2) **Verifier batch weights seeded from a transcript hash:** `shekyl-bulletproofs/src/derived.rs:130`, `shekyl-fcmp/src/batch_weights.rs:84`. (3) **Multisig values every signer derives from the transcript:** `shekyl-fcmp-proofs/src/sal/multisig.rs:157`. And one construction that is none of the three: `shekyl-fcmp/src/frost_sal.rs:465` seeds a `ChaCha20Rng` from `OsRng` drawn on the spot (`:462–463`), and that RNG only weights the batch verification of the aggregate signature (`sal/multisig.rs:307–315`); it never reaches a nonce. `CF-R12`'s G0 is that case. None of them is a signing or proving nonce taken from a fixed or caller-chosen seed, which is what the gate exists to refuse. A gate that refused every `from_seed` would refuse key derivation itself. **Disposition:** RULED (`CF-R12`): the gate lists sites, each under one of the groups G0…G3; built in `CF-1b` (§5.5).

---

## 3. The event catalogue

One row per chain feature a consumer needs. **Name** is the manifest's event name (§7.2), the interface consumers ask by. **Needs** is the schedule or difficulty the event constrains. **Status** is per row: AVAILABLE (a production path the forge can drive exists at the pin), BUILT-IN `CF-n` (the forge lane builds the missing piece in that increment), CHECK IN `CF-n` (whether the forge can carry it is a question that increment answers; the answer replaces the status), or WAITING (another lane's work; the blocker and the owner named). Paths are under `rust/shekyl-chain-ingest/src/` unless given in full.

| ID | Name | Event | Consumers | Lanes | Needs | Chain | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CF-E1 | `first-spend-1in-2out` | a 1-in/2-out spend | `vectors_tests/too_many_inputs.rs:57`; the 31 chain-sync loopback tests through `shekyl-p2p-harness/tests/chain_sync/support.rs:265`; `shekyl-chain-sync/src/scenarios.rs:88` | VAL, SYNC | any | L | AVAILABLE |
| CF-E2 | `first-spend-8in` | an 8-in/2-out spend at `MAX_INPUTS` | `too_many_inputs.rs:57` (the ninth input refused); `shekyl-chain-store/src/store/prune_tests.rs:825`; `PB-D1` shape 2 | VAL, DRS, PB | any | L | AVAILABLE (`Spender::spend_coinbases`) |
| CF-E3 | `first-spend-16out` | a 1-in/16-out spend at `MAX_OUTPUTS` | `vectors_tests/h19_cost.rs:43`; `PB-D1` shape 4 | BENCH, PB | any | L | BUILT-IN `CF-4` (the spender pays two outputs today, `spender.rs:656–701`) |
| CF-E4 | `block-at-weight-bound` | a block at the consensus weight bound | `limit-full`'s readers (`h19_cost.rs:43`, `corpus_census.rs:103`) | VAL, BENCH | any | L | AVAILABLE |
| CF-E5 | `block-at-median` | a block filled to the median | `median-full`'s readers | VAL | any | L | AVAILABLE |
| CF-E6 | `tree-depth-3` | the curve tree reaches depth 3, and a spend proves over it | `spend-depth3`'s readers | CT | about 750 blocks of outputs | L | AVAILABLE |
| CF-E7 | `seed-boundary` | the RandomX seed changes at 2,112 (epoch 2,048, lag 64), and a spend lands after it | `service_tests.rs:615`, `:2994`; `service_seed_tests.rs:490`; `vectors_tests.rs:747` | DRS | past 2,112 blocks | L | AVAILABLE |
| CF-E8 | `burn-positive` | the burn and the pool half turn non-zero | `vectors_tests/relay_floor.rs:45`; the burn oracle (`docs/FOLLOWUPS.md:355`) | ECON | past about 2,600 blocks of the young curve | L | AVAILABLE |
| CF-E9 | `first-complete-tree-join` | a complete-tree JoinMarket | `archival_corpus_tests.rs:196`; `archival_sufficiency_tests.rs:103` (the Bond witness) | ARCH | any | L | AVAILABLE |
| CF-E10 | `shard-<k>-closed` | shard `k` closes (about 227 spends) | the 13 nightly fills (§0.1); `regtest_e2e.rs:4832`, `:5061` | ARCH, SO-D12, DRS | any | L (shards 0–2) | AVAILABLE (`scenario_shard::close_shards`) |
| CF-E11 | `first-compact-join` | a compact JoinMarket on closed, final, priced shards | `scenario_join_tests.rs:67`; `pool_submit_tests.rs:305`, `:378` | ARCH | an epoch close after the shard closes | L | AVAILABLE |
| CF-E12 | `first-serve-credit` | serve credits with a real countersignature, admitted through bundles at the staged door | `scenario_emission_tests.rs:125`; the 18 padded-credit store tests; `archival_sufficiency_tests.rs` (ServeCredit) | SO-D12, DRS | the settled schedule | L | BUILT-IN `CF-2` (the countersignature, `CF-F6`) |
| CF-E13 | `first-settled-epoch` | an epoch closes and settles with non-zero RMarket, SigmaWork and Budget | `archival_sufficiency_tests.rs:96–121`; `ARCHIVAL_SETTLEMENT_WRITER.md:1093–1100`; #1360's emission-claim row | SO-D12, BENCH | the settled schedule | L | AVAILABLE once CF-E12 is |
| CF-E14 | `first-claim` | an emission claim | `scenario_emission_tests.rs:125`, `:628`; `archival_pop_roundtrip_tests.rs:88`, `:311`; `regtest_e2e.rs:4303` (DARK) | SO-D12, ECON | after CF-E13 | L | AVAILABLE (`emission_assembly`) |
| CF-E15 | `first-slash` | a missed-epoch slash, and the LastSlashEpoch watermark | `archival_slash_tests.rs:691`; `archival_pop_roundtrip_tests.rs:182`; `archival_sufficiency_tests.rs:315` | ARCH, SO-D12 | `FAILURE_WINDOW_M` missed epochs plus grace (`chain_drive.rs:99–102`) | L | CHECK IN `CF-4`: every witness today runs on the 20-block levered schedule (the slash with lever-issued draws, `IssueDraws`); none runs on L's settled schedule with admitted draws |
| CF-E16 | `first-reinstate` | a Reinstate after the slash | `archival_pop_roundtrip_tests.rs:182`; `archival_slash_tests.rs:691` | ARCH | after CF-E15 | L | CHECK IN `CF-4`: every witness today runs on the 20-block levered schedule (the slash with lever-issued draws, `IssueDraws`); none runs on L's settled schedule with admitted draws |
| CF-E17 | `first-release` | a Release | `regtest_e2e.rs:4832`; `archival_pop_roundtrip_tests.rs:88` | ARCH | any | L | AVAILABLE |
| CF-E18 | `first-unstake`, `first-collect`, `first-retire` | unstake, collect, retire | `regtest_e2e.rs:5061` | ARCH, WAL | a claim window | L | CHECK IN `CF-4`: the driver has no unstake/collect/retire step today; the daemon walk drives them through the wallet. If the production builders are reachable from the spender, BUILT-IN `CF-4`; if they need the wallet engine, the row names the engine lane |
| CF-E19 | `shard-0-discarded` | shard 0's bodies discarded below the horizon, then a spend of an output in it | `rpc_store_facts_tests/below_horizon.rs:130`; `prune_tests.rs:825` | DRS-SB, DRS | past the body horizon | L | CHECK IN `CF-4`: every witness today runs on the 20-block levered schedule (the slash with lever-issued draws, `IssueDraws`); none runs on L's settled schedule with admitted draws |
| CF-E20 | `settled-on-discarded` | a later epoch settles over discarded bodies | Round 0's Chain L list | SO-D12 | after CF-E19 | L | CHECK IN `CF-4`: every witness today runs on the 20-block levered schedule (the slash with lever-issued draws, `IssueDraws`); none runs on L's settled schedule with admitted draws |
| CF-E21 | `prune-boundary-<n>` | a pruning boundary batch | `archival_pop_roundtrip_tests.rs:88`, `:182`, `:311` | DRS | any | L | AVAILABLE |
| CF-E22 | `reorg-shallow` | a depth-2 alt branch that wins, its spends returned to the pool | `regtest_e2e.rs:2104`; `pool_block_tests/mod.rs` (switch returns); `E5-10` | DRS | layout 4 | L | BUILT-IN `CF-3` |
| CF-E23 | `reorg-at-cap` | a switch at exactly the reorg cap (10) | `switch_tests.rs:475` | DRS | layout 4 | L | BUILT-IN `CF-3` |
| CF-E24 | `reorg-across-epoch` | a switch across an epoch boundary | `archival_pop_roundtrip_tests.rs:311`; `E5-9` | DRS, SO-D12 | layout 4 | L | BUILT-IN `CF-3` |
| CF-E25 | `reorg-across-prune` | a switch across a pruning boundary | `E5-9` (`DRS_E5_POOL_ALT_PRUNE.md:370–378`) | DRS | layout 4 | L | BUILT-IN `CF-3` |
| CF-E26 | `reorg-across-chunk` | a switch across a curve-tree leaf-chunk boundary (trim) | `regtest_e2e.rs:3119` | CT | layout 4 | L | BUILT-IN `CF-3` |
| CF-E27 | `wallet-outputs` | spends paying watched wallets and personas, so scans find real outputs | `rpc_store_facts_tests/reads.rs:362`; the `ct2_tier_*` fixtures' readers | WAL, CT | any | L | AVAILABLE (`Spender::own`) |
| CF-E28 | `producer-bundle`, `producer-support-bundle` | bundles made by the bundle producer, served by a persona through the production serve loop and the real countersigner | `bundle_producer_gate_tests.rs:333`, `:549` | SO-D12 | the producer's own epoch (`EPOCH_BLOCKS = 1,200`, `bundle_producer_gate_tests.rs:70`) | B | ACCEPTED, conditional on `CF-1c` (`CF-R10`): `CF-1c` lists what the producer depends on besides chain state and whether each is by design (§4) |
| CF-E29 | `design-load` | 30 two-in/two-out spends a block for 5,040 blocks, then a 4× segment | `scripts/bench/drs_catchup.py`, `drs_crash.py`, `drs_powerloss.py`, `drs_bench.py`; `docs/FOLLOWUPS.md:1375` | PB, WAL | the production schedule | P | BUILT-IN `CF-6` |
| CF-E30 | `switch-depth-10-loaded` | a depth-10 switch at design load (`PB-D4`) | `DAEMON_REDB_STORE.md` §1.3a.2 | PB | the production schedule | P | BUILT-IN `CF-6` |
| CF-E31 | `reorg-production-cap` | a switch at the production cap (720, plus one on the winning branch) | `switch_timing_tests.rs:165`, `:171`, `:180`, `:186` | DRS | the production cap | P | BUILT-IN `CF-6` |
| CF-E32 | `lwma-past-window` | LWMA-1 past its window, timestamps spaced so the target moves | `miner_tests.rs:425` (mines it); the E2 replay (`DRS_E2_REPLAY_DRIVER.md` §7 item 8) | ECON, DRS | live difficulty, no levers | W | BUILT-IN `CF-6` |
| CF-E33 | `first-multisig-spend` | a scheme-2 (multisig) spend | `PB-D1` shape 3 (`DAEMON_REDB_STORE.md` §1.3a.7) | PB, multisig | any | L | WAITING: the multisig E′ lane (`V3_1_MULTISIG_RUST_ENGINE.md` §9, slices 3–4). Blocker: no scheme-2 spend through a wallet-side builder the spender can drive; `frost_spend.rs` is a crypto-level test. FROST nonces need a seed seam of their own when it lands (§5) |
| CF-E34 | `first-attestation` | a block carrying an attestation witness (`0x0B`) | `docs/FOLLOWUPS.md:363` | SO-D12, SYNC | any | L | WAITING: `ARCHIVAL_CREDIT_WIRE.md` (the producer) and `RPC_WIRE.md` RW-Q5 (the sidecar). Blocker: no producer emits `0x0B`, and the witness is a wire sidecar the corpus does not carry |
| CF-E35 | `max-bundle` | a block's serve-credit bundle at its maximum record count (`PB-D1` shape 8) | `DAEMON_REDB_STORE.md` §1.3a.7 | PB, SO-D12 | any | stress mode | WAITING: SO-D12 4b builds the bundle (§1.3a.7 says so) |

Out of the catalogue on purpose: chains built from `harness::fixture` bodies and mocks (`shekyl-chain-rules`, the store's connect and view tests, `pipeline_tests.rs`), which test mechanics, not a realistic chain; and the `PB-D1` adversarial shapes 1–7, which are blocks, not a chain (the stress-mode increment).

---

## 4. The chain set — from §3 (`CF-R1`, `CF-R10`)

Four chains, split where needs conflict (`CF-R10` accepts B conditionally); L's own split is undecided until `CF-4`:

| Chain | Schedule | Difficulty | Length | Carries | Storage (§10) |
| --- | --- | --- | --- | --- | --- |
| **L** — lifecycle | the settled schedule (`settled_epoch_blocks()`, derived ≈ 300; cap 10) | fixed 1 | about 4,500 blocks (estimate) | CF-E1…E27, and CF-E33/E34 when they land | GHCR, pinned by digest (`CF-R6`, `CF-R11`) |
| **B** — bundle producer (ACCEPTED, conditional on `CF-1c`; `CF-R10`) | the producer's epoch (1,200; cap 10) | fixed 1 | about 3,600 blocks (three epochs) | CF-E28 | as L |
| **P** — production under load | production (10,000; cap 720) | fixed 1 | 5,040 blocks plus the stress segment, plus the alt branches of CF-E30/E31 | CF-E29…E31 | GHCR, pinned by digest |
| **W** — LWMA | production, no levers | live LWMA-1, real RandomX | a few hundred blocks | CF-E32 | committed |

**Whether L carries the slash too: undecided until `CF-4`.** Today's slash tests run on the 20-block levered epoch with lever-issued draws, because each test pays for its own chain and 12 epochs of 20 blocks is cheap. A forged chain is paid for once, so L could carry it on the settled schedule. The estimate: shard 0 closes near block 300 (about 227 spends, behind coinbase maturity); a compact join is priced at an epoch close near block 600; a persona that never serves then misses `FAILURE_WINDOW_M` = 11 epochs (of `N` = 13 observations, `config/consensus_constants.json`) and the grace epoch (`SLASH_GRACE_EPOCHS` = 1), so the slash lands near block 4,500. Two things are unproven. No test drives a slash, a reinstate or a discard on the settled schedule with admitted draws. And the settled derivation guarantees every pair its draws only up to `SETTLED_PAIRS = 2` (`scenario_shard.rs:78`): L's personas must hold at most two drawable pairs between them (one serving, one missing), and whether a complete-tree holder's support stream counts against that is unchecked. `CF-4` forges the slash on the settled schedule first. If it does not hold, L splits into a settlement chain and a slash chain on the levered schedule, and this table records why.

**Why B is its own chain.** The producer cannot run on L's schedule (`CF-F8`: `W₂` 15 < `FILING_MARGIN` 30). B is ACCEPTED, conditional on `CF-1c` (`CF-R10`). Its bundles come from reads a persona serves over loopback, with start delays (`shekyl-chain-ingest`'s `producer` feature, `tokio/time`). `CF-1c`'s audit lists everything the producer depends on besides chain state (read timing, the fetch scheduler's draws, the serving persona's clock) and says, for each, whether the dependence is by design. If it is not, the dependence is filed with SO-D12 as a producer defect. If it is, two things hold, because B is hosted like L and its artifact is a cache of a byte-identical regeneration (§10.3, §10.4):

- **B's bytes stay deterministic.** The forge records each such input in B's plan (the read delays, the scheduler's draws, the persona's clock readings) and drives the producer from the record, so a regeneration at the pinned commit reproduces the corpus and its SHA-256 pins, and a deleted artifact is rebuilt like any other.
- **`CF-R10`'s state comparison is the live cross-check's, on a named projection.** A run of the producer under its real timing cannot match B's bytes and is not asked to. It is held to B on the settlement outcome: per settled epoch, the admitted draws, the passes filed, the bond records and the settlement and budget rows. It is not held on `logical_state_digest_v0`, which hashes every block hash (`shekyl-chain-store/src/digest_v0.rs:15–31`), so it differs whenever a bundle's bytes or its block do; a block-carried bundle's reference moves with its receipts (`shekyl-archival-retention/src/bundle.rs:791–824`). `CF-1c` names the projection's rows and gives it a negative control: two runs whose settlement differs in one admitted draw are told apart.

If an input cannot be recorded, B cannot be regenerated byte for byte, and `CF-1c` brings B back to Rick with a durable-artifact policy instead of hosting it as a cache.

**Why P carries the production-cap reorgs.** They need the production cap (720), and P is the chain on the production schedule. They are also measurements (`switch_timing_tests.rs` times them; `PB-D4` is a budget row), which is P's purpose.

**Why W has no levers.** LWMA moves only under live difficulty, so W is forged with the production substrate (real RandomX) and a nonce search from zero. The first satisfying nonce is a function of the blob, so W stays deterministic. W pulls no lever, so its identity rests on §6's locks 2–4.

The constraints this decision rests on:

| Constraint | Source | Effect |
| --- | --- | --- |
| Settlement through admitted draws needs the settled schedule (SEB ≈ 300) | `scenario_shard.rs:80–125` | the settled-epoch events share one schedule |
| The bundle producer cannot run on the settled schedule (`W₂` 15 < `FILING_MARGIN` 30) | `scenario_shard.rs:110–117` | producer-made bundles are a different schedule |
| A slash needs `FAILURE_WINDOW_M` missed epochs plus the grace epoch | `chain_drive.rs:99–102`; `SLASH_GRACE_EPOCHS`, `shekyl-archival-retention/src/constants.rs:43` | on the settled schedule, about 12 × 300 blocks after the join is priced |
| Fixed difficulty and live LWMA are mutually exclusive in one chain | `DRS_E2_REPLAY_DRIVER.md` §7 item 8 | the LWMA chain is separate |
| The production schedule (10,000-block epoch) never settles inside a test-sized chain | `CappedEpoch::PRODUCTION` | Chain P carries load, not lifecycle |
| Crossing the RandomX seed boundary (block 2,112: seed epoch 2,048, lag 64) | `DRS_E2_REPLAY_DRIVER.md` §7 item 8 | any chain past 2,112 blocks crosses it |

---

## 5. The determinism contract and the seed seams

### 5.1 The contract

A forged chain is a pure function of three inputs: the **plan** (TOML, committed), the **plan's seed** (32 bytes, written in the plan), and the **commit** the forge is built at. Same three, same bytes. Every non-deterministic input that can reach a block's bytes is either fixed by the driver (the clock, the nonce), derived from the plan's seed by a domain-separated derivation, or ordered by a structure whose order is defined (no hash-map iteration, no thread scheduling in anything that reaches a block).

The derivation is one function in the forge: `seed_for(plan_seed, role, index) = cSHAKE256(S = "shekyl/chain-forge/seed-v1", X = plan_seed ‖ role ‖ index)[..32]`, one `role` string per consumer of randomness (`"miner"`, `"persona"`, `"wallet"`, `"tx"`, `"prover"`, `"signer"`, `"witness"`), so two roles never share a stream and adding a role does not move another role's bytes. Its domain string joins `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` in `CF-1c`, with the binding `local:test-only forge seed`.

### 5.2 The sources, read at `4b867a4f8`

A transaction's id covers its proofs and signatures, so one random byte in any of them moves the txid, the block's transaction list, the block hash, the next block's `previous`, the RandomX seed two thousand blocks on and every later spend's reference. Every row below therefore changes a forged chain's bytes from its first use onward.

| # | Source | Where | What it reaches | Takes an RNG today? |
| --- | --- | --- | --- | --- |
| S1 | Bulletproofs+ range proof | `shekyl-tx-builder/src/sign.rs:134`, `prove_plus(&mut OsRng, ..)` inside `sign_transaction_with_terms` (`:105–114`) | the prunable region of every spend, bond post and emission fee side | `prove_plus` is generic over `R`; `sign_transaction_with_terms` has no RNG parameter |
| S2 | Pseudo-out blinds | `sign.rs:168–175`, `Scalar::random(&mut OsRng)` for every input but the last | pseudo-outs and the proof, **multi-input spends only**; one input takes only the `else` arm and is deterministic | no |
| S3 | FCMP++ proof (SAL nonces, rerandomization, branch blinds) | `shekyl-fcmp/src/proof.rs:630–637`: `prove` calls `prove_with_rng(&mut OsRng, ..)` | every spend's membership proof | **yes, publicly: `prove_with_rng<R>` is `pub`** (`proof.rs:519–527`); see `CF-F12` |
| S4 | Emission backing proof | `proof.rs:711` (rerandomize), `:722` (MSA), `:730` (circuit) | the emission vin, which sits in the prefix: prefix hash, both auths, txid | no. `:711` and `:722` are hedged (`synthesize_scalar`, Blake2b over the secret and fresh bytes), but the fresh bytes still change every call |
| S5 | ML-DSA-65 half of every hybrid signature | `shekyl-crypto-pq/src/signature.rs:441–452`, `pk.try_sign(inner, &[])`, fips204's OS-drawn `rnd` | spend `pqc_auths`, the bond slot (`shekyl-harness-spender/src/bond.rs:67–73`), both emission auths, the emission slot | no in production; seeded variants exist behind `test-utils` (`signature.rs:386–400`; `output.rs:1110–1133`) |
| S6 | Ed25519 half of the hybrid signature | `hybrid_combiner.rs:75–88` (RFC 8032, deterministic) | the same slots | deterministic, but it signs `inner ‖ σ_pq`, so it inherits S5's randomness |
| S7 | The witness ring's draw commitment | `scenario.rs:841–846` → `shekyl-bundle-producer/src/ring.rs:72–88` (an OS key pair and an `OsRng` seed) | the coinbase's `0x0C` field, so the block hash; only when a scenario calls `draw_from` | no; deterministic alternatives already exist (`commit_next`, `scenario.rs:224`, with `DriverWitness` from fixed seeds, `admitted_draws.rs:58–64`) |
| S8 | FN-DSA bundle witness and receipt signatures | `fn_dsa_hybrid.rs:381–424` (`sign` over `HedgedOsRng`) | bundle bodies, so `prunable_hash` and the store's queue rows. **Not block bytes at this commit** (no block carries a reference until SO-D12 4b, `connector_bundles.rs:32–33`); block bytes once 4b lands | private generic `sign_with_rng`; seeded `sign_with_rng_seed` behind `test-utils` (`:394–408`) |
| S9 | The shard fill's parallel spend building | `scenario_shard.rs:418–436`: `thread::scope`, joined in spawn order | list order is already fixed; each thread's spend draws S1–S6 from the OS | n/a: order is deterministic; the content is S1–S6's |

**Already deterministic on the forge path** (the sweep's list, spot-checked): the coinbase transaction secret (a per-template counter, `scenario.rs:839–840`, `:889–890`) and its zero extra nonce (`:927`); every output's ephemeral key, ML-KEM encapsulation seed, commitment mask, encrypted amount and label, view tag and leaf, all derived from the transaction secret (`shekyl-crypto-pq/src/output.rs:245–385`); the spend's transaction secret (height and key image, `spender.rs:674–688`); the emission's transaction key (passed in, `emission_assembly.rs`); the miner's and personas' keys (fixed seeds); bond vins (no RNG in `shekyl-archival-bond-builder`); the timestamp (the driver's clock from 1,800,000,000 in 120-second ticks, `scenario_types.rs:26–72`); the nonce (0; fixed difficulty 1 means no search, `scenario.rs:141–152`); input order (sorted by key image, `spender.rs:633`); listed order (the caller's `Vec`; no hash-map iteration forms a block or picks a transaction).

**Open in the audit (`CF-1c`):**

- **Alt-branch store paths iterate hash collections**: `shekyl-chain-store/src/store/alt_reads.rs:76–98` (`children: HashMap`, `closure` returns a `HashSet`) and `alt_view.rs:143`. No block bytes come from them, but a reorg's store rows, and so the trace digest, might. `CF-1c` reads each use; any whose order reaches a written row is ordered, or shown order-free with a test.
- **Cross-architecture key generation**: whether `HybridEd25519FnDsa::keypair_from_seeds` gives identical keys on x86_64 and aarch64 is not traced. A persona's receipt key comes from it and a JoinMarket commits that key (`persona.rs:112–117`). `CF-1c`'s gate forges the small plan on both architectures and compares, on the estate's aarch64 hosts (the Pi 4 floor, rule 76, is aarch64).
- **The rules fixture's memoized signatures** (`shekyl-chain-rules/src/harness/fixture/mod.rs:700–733`) are stable within one process and differ across processes. The forge must not build bodies through the fixture (`Growing::anchored` reaches it); it builds every body through the spender and the production builders. `CF-1c` asserts that with the twice-forged gate run as two processes, not one.

### 5.3 The seams, and why none is reachable from a shipped binary

**The boundary.** "The production prover and signers keep OS randomness with no injectable RNG in their public API" is held at the Shekyl-owned entry points that the wallet, the daemon and the CLI call: `shekyl-tx-builder`'s signing functions, `shekyl-fcmp`'s `proof` module, and `shekyl-crypto-pq`'s signature schemes and output signers. The vendored primitives below them (`Bulletproof::prove_plus`, `Fcmp::prove`, the SAL prover) are generic over `R: RngCore + CryptoRng`, as they are upstream. That bound refuses a non-cryptographic RNG at compile time, and a seed has to be threaded through a Shekyl entry point to reach them. RULED (`CF-R9`): the line sits there.

**The shape, one per crate: crypto-pq's FN-DSA pattern.** `HybridEd25519FnDsa` already has the right shape (`fn_dsa_hybrid.rs:381–424`). A **private** generic body takes the RNG (`sign_with_rng`), the production entry point passes `HedgedOsRng` (`sign`), and a seeded entry point exists only under a test-only `cfg` (`sign_with_rng_seed`). The forge's seams copy it:

| Seam | Crate | Production entry point (unchanged signature, OS randomness) | Seeded entry point (test-only feature `seeded-rng`) | Covers |
| --- | --- | --- | --- | --- |
| T1 | `shekyl-fcmp` | `proof::prove`, `proof::prove_backing_membership` | `prove_seeded`, `prove_backing_membership_seeded`, over a private generic body | S3, S4 |
| T2 | `shekyl-tx-builder` | `sign_transaction_with_terms`, `prove_backing_membership`, `open_spend` | the same names with `_seeded`, taking a seed, threading it to T1, BP+ and the pseudo-out blinds | S1, S2, S3, S4, and S5 for `pqc_auths` through T3 |
| T3 | `shekyl-crypto-pq` | `SignatureScheme::sign`, the output signers | `sign_with_ml_dsa_seed` and `sign_pqc_auth_for_output_with_ml_dsa_seed` (exist today under `test-utils`), and `sign_with_rng_seed` (FN-DSA) | S5, S6, S8 |
| T4 | `shekyl-harness-spender` | n/a (test support; reached from dev edges only) | `Spender` and `Persona` built with a seed take the seeded entry points throughout | every spend, post, claim and credit the forge builds |
| T5 | `shekyl-chain-ingest` | n/a | a test-only `forge` feature that compiles `scenario`, `scenario_shard`, `scenario_archival`, `chain_drive` and `emission_assembly` for an outside caller, with the witness drawn by `commit_next` and `DriverWitness` from the seed (S7) | the driver itself (`CF-F2`) |

Each seed is `seed_for(plan_seed, role, index)` (§5.1), with `index` the spend's or signature's position in the plan, never a thread or a counter that depends on scheduling. S9's threads each receive their spend's seed before they start.

**`CF-F12` — `shekyl-fcmp::proof::prove_with_rng` is public today**, the one Shekyl-owned prover entry point that takes an RNG. Its doc says it exists so an instruction-count bench can pin a seeded RNG (`proof.rs:519–525`), and its one caller outside the crate is `shekyl-verify-cost`'s drift fixture (`shekyl-verify-cost/src/relay.rs:331`), on a normal edge. `CF-1b` makes it crate-private behind the test-only `seeded-rng` feature (`CF-R9`), in T1's shape. `shekyl-verify-cost` enables the feature, on a dev edge as the gate requires: it is a bench crate, and the code calling the seeded entry point moves into its bench target where it is in the library today. After `CF-1b`, no normal edge in the workspace reaches a Shekyl-owned prover entry point that takes randomness from its caller.

**Why none is reachable from `shekyld`, the wallet or the CLI.**

1. **Compile-time absence.** Every seeded entry point is `#[cfg(feature = "seeded-rng")]` (T5's `forge`), so a build that does not enable the feature has no such symbol. A production call site that named one would not compile. This is the property the rules fixture's comment asks for (`fixture/mod.rs:706–709`: "the crypto surface should not offer production code a way to sign without randomness"); it holds because no production build *has* the surface, not because the surface is unused.
2. **Each feature is TEST_ONLY in the gate.** `seeded-rng` on T1–T4 and `forge` on T5 get `TEST_ONLY` rows in `check_test_only_features.py`. No normal or build edge may enable them, the owner's own features may not, and at least one dev edge must (the gate's three limbs). Their only enabler is `shekyl-chain-forge`'s `[dev-dependencies]`, plus `shekyl-verify-cost`'s for T1.
3. **The forge is a test-kind target** (§11.1). No `[[bin]]` exists to link them.
4. **The production graph check** (§11.1 item 2) asserts over `shekyld`, `shekyl-cli` and `shekyl-wallet-rpc`'s resolved normal and build graphs that no `seeded-rng` or `forge` feature is on and no harness crate is present.

**Two things this rests on, both in `CF-1b` (`CF-R10`):**

- **`test-utils` today is not a TEST_ONLY row.** `shekyl-crypto-pq` sits in the gate's shrink-only grandfather list (`check_test_only_features.py:464–476`), because `shekyl-p-serve`'s `test-signer` forwards `test-utils` over a normal edge (FOLLOWUPS F-7, `F7_TEST_ONLY_FFI_EXPORTS.md`). A new enabler on a listed crate is red, so the forge cannot simply enable `test-utils`. `CF-1b` takes `shekyl-crypto-pq` into `GOVERNED_OWNERS` with `seeded-rng` as a TEST_ONLY row. That requires F-7's remaining normal-edge hits on the crate to be resolved first: `shekyl-p-serve`'s forward, and any direct normal enabler. The forge lane does that in `CF-1b`, coordinating with F-7's owner, rather than building on the grandfathered feature.
- **The gate's forwarding fix (`CF-F5`).** T2 forwards T1 and T3's features, and T4 forwards T2's, each over a normal edge from a feature that is itself TEST_ONLY. The gate must classify those forwards by every edge the alias names, and accept a forward only when its source feature is TEST_ONLY too (§5.4).

### 5.4 The gate the seams rest on (`CF-F5`, fixed in `CF-1b`)

`CF-1b` changes `enablements()` in `check_test_only_features.py` to record a forwarded activation once **per edge** the consumer has to the owner, not once for the last edge its manifest lists. A forward over a crate that is both a normal and a dev dependency is then seen on the normal edge, where Cargo applies it.

That alone would turn two live forwards red (`shekyl-chain-ingest/harness` → `shekyl-chain-rules/harness`, `shekyl-mempool/pool-commit-fault` → `shekyl-chain-store/pool-commit-fault`), which are safe because their source is TEST_ONLY. So the TEST_ONLY limb, moved out of `main()` into a function so that its own selftest can reach it, accepts a non-dev forward exactly when the forwarding feature is itself a `TEST_ONLY` row: that row's own limbs already keep it to dev edges, so the forward is on only in builds the row allows. A forward from any other feature over a normal edge is red, which is the hole this closes. The selftest gains both shapes: the dual-edge forward from an ordinary feature (red; green before the fix) and the forward from a TEST_ONLY feature (green).

### 5.5 The seedable-RNG gate (`CF-R9`, built in `CF-1b`)

**Subject.** A seedable generator constructed in production code: `SeedableRng::from_seed`, `seed_from_u64`, `from_rng`, and a crate's own seeded constructors (`SeededRng::from_seed`, `keygen_from_seed`, `keypair_from_seeds` and their kin), found by a source scan of every workspace crate's non-test code. "Production code" excludes `#[cfg(test)]` items, `tests/`, `benches/` and `examples/` targets, and items under a `TEST_ONLY` feature's `cfg`. The scan reads `cfg` attributes, not file names, because inline test modules sit in production files.

**Verdict (RULED, `CF-R12`).** A construction outside test-only code is red unless its **site** is listed: by path and function, with its group and one line on where its seed comes from. A group's name allows nothing on its own. The groups, and the only seed sources the list accepts:

- **G0 — drawn from `OsRng` on the spot.** The seed is fresh OS randomness at the call (`shekyl-fcmp/src/frost_sal.rs`, `algorithm()`, whose seed only weights the batch check of the aggregate signature). Listed anyway, so the gate never has to guess.
- **G1 — key derivation.** The seed is the output of a key-derivation function over a secret key or seed, and determinism is the point: the same seed must give the same keys (`CF-F14`'s first class).
- **G2 — verifier batch weights.** The seed comes from a domain-separated transcript, and what it seeds is weights only, never a value that is published or signed (`shekyl-bulletproofs/src/derived.rs`, `shekyl-fcmp/src/batch_weights.rs`).
- **G3 — multisig values every participant derives identically,** from a transcript that already binds every participant's commitments (`shekyl-fcmp-proofs/src/sal/multisig.rs`, `sign_share`, below).

**Always refused, at any signing or proving nonce:** a constant seed, a seed the caller chooses, or a seed built from public data alone. A fixed seed exists only through the test-only `seeded-rng` feature (§5.3).

**No grandfathering.** At `CF-1b` every current hit (about 130 at `4b867a4f8`) is either listed with its justification or changed. A later site needs a reviewed change to the list. The list keys on path and function, so a file move drops a site's listing and sends it back to review, on purpose.

**The SAL multisig site (G3).** `sign_share` derives α, β, δ, μ, r_z, r_p and r_r_p from `ChaCha20Rng::from_seed(transcript.rng_seed(b"deterministic_nonces"))` (`sal/multisig.rs:156–178`). Those cover parameters that are not secret within the signing group, which is the upstream FCMP++ SAL design; only `y` is the threshold secret, and its nonce comes from FROST's hedged preprocess step (the `nonces` argument). `CF-1b` meets two conditions before the site is listed:

1. a test that fails if the `y` nonce ever comes from the `deterministic_nonces` stream;
2. a reading, in code, that the transcript binds every participant's preprocess commitments before `rng_seed` is called, recorded in the listing with its line. That binding is what rules out reusing a derived value across signing sessions. It is unverified as of this document.

**The gate asserts its own subject** (rule 47). Its selftest plants an unlisted `seed_from_u64` in production code and expects red, plants one under a test-only `cfg` and expects green, plants a listed site at a moved path and expects red, and fails if a listed site no longer exists (a row must name live code).

---

## 6. Regtest identity

**What changes from today's driver (`CF-F1`).** The forge mines under `ChainRules::new(Network::Regtest, fixed_difficulty, schedule)`, never `unpinned()` or `harness_regtest`. Its genesis pin is then `GenesisPin::for_network(Regtest)` (`schedule.rs:76–105`), and:

- **Block 0 is regtest's table genesis.** The forge assembles it from `Network::Regtest`'s genesis transaction (`shekyl-network/src/genesis.rs`, `Genesis::tx_hex`) under the fixed genesis header, as the node assembles it, and connects it through the same door as every other block, where CEN-E1 holds it to the pin. The forge mines nothing at height 0.
- **Every signature and proof is bound to regtest's id.** Spends, bond posts, emission claims and serve credits sign and prove over `tx_signable` framed with `Network::Regtest.network_id()`, the id derived from regtest's genesis (`NI-R10`, `NI-R17`). The spender is built for a network (`Spender::on`, `CF-1a`) and every output it sources carries that id; the emission assembly takes it with the proof reference (`ClaimAnchor`). The harness id stays only for the unpinned fixture chains until they migrate (§12).
- **Every key derives under regtest's name.** Personas, the miner and the wallets the forge pays derive from `seed_for(plan_seed, role, index)` under `Network::Regtest`'s name (`NI-R10`, `NI-R16`), not `Persona::at`'s mainnet derivation from the fixed `[0x51; 64]` master (`persona.rs:58`, `:69`). `Persona::at` keeps its mainnet derivation for the fixtures that pin persona ids until those fixtures migrate (`persona.rs:55–57` says the ingest's replica fixtures name them by id).
- **The harness seed is public and regtest-only** (`CF-R15`). The regtest miner is the wallet `account_from_seed` derives on regtest from `HARNESS_SEED`, a constant every test binary carries (`shekyl-harness-wallet`, `MinerWallet::harness_regtest`). Anyone who restores that seed can spend the regtest chain's coinbases, and that is intended: a forged chain's coins have no value off regtest. Its addresses carry regtest's prefixes, so a mainnet, testnet or stagenet wallet refuses them as another network's (`AddressError::NetworkMismatch`), and `shekyl-harness-wallet` `tests::the_regtest_miners_address_is_refused_off_regtest` holds that refusal, beside regtest's own acceptance (added in `CF-1a`).
- **The corpus header's `net` byte is regtest's code** (`corpus.rs`, "The corpus's `net` tag"), and the manifest records `"network": "regtest"` and regtest's genesis hash.

**Why a forged chain cannot validate elsewhere — four independent locks, each asserted by the identity test (`CF-1a` on a driver-built chain, `CF-1c` on the forge's small plan, `CF-4` on Chain L):**

1. **The levers.** Fixed difficulty, a settlement epoch other than production's and a reorg cap other than production's are permitted by regtest's row alone (`NI-R6`; `ChainRules::new` returns `LeverRefused` for any other network, `schedule.rs:76–98`). The test asks for the chain's own `(fixed_difficulty, schedule)` under testnet, stagenet and mainnet and asserts the refusal. Chain L and Chain P are fixed-difficulty, so this lock alone stops them. The LWMA chain pulls no lever, so it rests on locks 2–4.
2. **Genesis.** Replayed under testnet's, stagenet's or mainnet's rules (production schedule, no levers), block 0 is refused by CEN-E1 against that network's pin. The test asserts the refusal at height 0 and names the row.
3. **Signatures.** For every transaction in the chain, its hybrid signatures and its proofs fail verification under each other network's id. This holds even for a validator that skipped the genesis pin: the test checks transaction by transaction, not just the first refusal. The full stateless judgement names the signatures first (CEN-I18), so the proof leg is judged on its own (`judge_claimed_proof`), where the row is the class's proof row: CEN-I15 on a spend, CEN-J26 on an emission, CEN-J27 on a bond post.
4. **The wire.** A node of another network does not handshake with a regtest node (`PWD-T5`'s prefix from the network id, `shekyl-network/src/lib.rs` `prefix_for`), so a forged chain cannot even be offered to one. This lock is the network's, not the forge's; the identity test cites it by path and function (`CF-R15`): `shekyl-clearnet/src/tests.rs`, `a_listener_refuses_every_other_networks_prefix_and_takes_its_own`, a listener of each network that refuses every other network's prefix after zero bytes and seals a handshake opened with its own (added in `CF-1a`).

---

## 7. The corpus: binary layout 4, manifest 5

### 7.1 Alt branches (`E5-10`)

Today a corpus can say *pop* (`rewind`) but not *a competing branch arrived* (`E5-10`; `IngestEvent` is `Extend`, `Rewind`, `Inject`, `source.rs`). A real node meets a reorg as alternative blocks that it holds, judges with the fork choice, and switches to when the alternative is heavier. Layout 4 adds one record for that:

```text
offer = 0x04 ‖ block_len u32 ‖ block ‖ tx_count u32 ‖ (tx_len u32 ‖ tx)*
```

An `offer` is a block that arrived and does not extend the corpus's tip. Its parent is named by its own header (`prev_id`): a main-chain block or an earlier `offer`. The reader emits it as a new `IngestEvent::Offer`, and the pipeline hands it to the connector's alternative door (`OfferAlt`, the path `Scenario::offer` already drives, `scenario.rs:494–516`). **No record says "switch".** A corpus is network-shaped only (`corpus.rs` module docs: no facts, no verdicts), so whether and where the chain switches is the pipeline's fork choice, derived on replay and recorded in the trace (`RunReport::switches`). The manifest says where the forge *expects* each switch (§7.2), and the replay test holds the two equal. A switch that did not happen, or happened elsewhere, is a change in the fork choice, which is what the record exists to catch.

The writer keeps its RD-F15 check on an `offer` (bodies match the header's list in count, order and hash), and the reader re-derives it, as for `extend`. The `rewind` record stays: it is the pop family's own subject (DRS-E2 §7 item 8c).

**Layout 4 is the binary change, so `CORPUS_FORMAT_VERSION` moves 3 → 4** (`CF-F3`). RULED (`CF-R7`): the layout-4 reader also reads layout 3 until the last layout-3 corpus is gone, and the layout-3 arm is deleted in that change. The arm is migration code under rule 15's lifecycle, its deletion trigger named in the code. No old corpus is re-captured from a live daemon to get there.

### 7.2 The manifest, format 5

Format 4's fields stay (`regtest_e2e.rs:5831–5885`). Format 5 adds:

| Field | What it is |
| --- | --- |
| `chain` | `L`, `P`, `W` (LWMA) or a further chain §4 adds |
| `plan` | the plan file's path in the tree and its SHA-256 |
| `seed` | the plan's 32-byte seed, hex (also in the plan; repeated so the manifest alone names the chain) |
| `forged_at` | the commit the forge was built at, as `built_at_dev_sha` is today |
| `network`, `genesis_hash` | `regtest` and its table genesis (§6) |
| `schedule` | `settlement_epoch_blocks`, `reorg_cap_blocks`, `fixed_difficulty` (or `null` for live LWMA) |
| `corpus_sha256`, `trace_sha256` | the layers' hashes; the pin file repeats them for a hosted chain, and the fetch script and the snapshot key read them (§8, §10.4) |
| `events` | the event index: one row per indexed event, `{ "name": "first-settled-epoch", "height": 1203, "branch": "main", "record": 1219 }`; `branch` is `main` or `alt:<n>`; `record` is the record's position in the corpus |
| `switches` | the switches the forge expects: `{ "at_record": k, "fork_height": h, "depth": d }` |

An event's **name** is the stable interface. A consumer asks for "the chain up to `first-claim`" and never for a height, so a regeneration that moves heights leaves every consumer's code as it was. The names are `CF-E` rows' names (§3); renaming one is a breaking change to every consumer and is done as one.

Beside the manifest, the chain carries **`blocks.txt`**: one line per block in corpus order, `height branch block_id`. It is the chain's KAT ledger (§9): small (about 70 bytes a block), diffable in a pull request, and the first line that differs is the first differing block.

### 7.3 What a corpus may hold that no block carries (`CF-F10`)

A forged chain is block-derived wherever a production path exists: serve credits through admitted bundles (`chain_drive::mine_serving`'s witness, then the staged door), draws through admission. A regtest lever write (`IssueDraws`, the serve-credit `inject`) is used only where no production path exists yet. Each is a corpus record and a manifest `out_of_band_writes` row, as `inject` is today, so a replay reproduces it and a reader sees that the chain is not wholly block-derived. `IssueDraws` has no record today; if §3 needs it, `CF-3` adds one under the same law as `inject` (`at` is the tip at the record's position; refused under any network whose row does not permit the lever).

---

## 8. The snapshot cache

A consumer that needs "the state at `first-settled-epoch`" opens a copy of a store that a full replay left at that event, instead of replaying a thousand blocks itself.

- **Built only by the production path.** `shekyl-chain-replay replay` over the corpus, under `ProductionSubstrate` (real RandomX verification, the production validator, every proof checked), stopped at the event's record; the store file is then copied aside. Nothing writes a snapshot any other way, and nothing trusted is skipped: this is the constraint "nothing trusts a store it did not verify".
- **Verified on open.** The trace carries a store digest at **every indexed event**, keyed by the event's corpus record (the manifest's `record`, §7.2), not by height: a rewind and its re-extension put a different block at the same height, and an `offer` or `inject` record changes state without moving the tip. The replay captures it immediately after that record. That is not today's `RunReport::digests`, which is keyed by height and pruned on a rewind (`pipeline.rs:1284–1286`). The digest covers **every table the snapshot holds**, as the store holds them (`ChainStore::table_rows`, `store/read.rs:1059`, the read the pop round trip already compares), under its own version. `logical_state_digest_v0` is not enough: it hashes block hashes, spent key images and the curve root only, and leaves the archival, output and alt-chain tables out by design (`digest_v0.rs:15–31`), while the snapshots' consumers read exactly those. The open helper recomputes the digest over its copy and refuses one that is not the trace's at that record. Its negative control is a snapshot with one archival row edited and the chain unchanged, refused. The trace is committed with a small chain and pinned by its layer's SHA-256 with a hosted one (`CF-R13`), and the corpus hash is pinned either way, so a stale or edited snapshot fails here, whatever the cache key said. Adding checkpoints at event records, and the store digest itself, is a trace-layout change; it bumps the trace's own version in `CF-4`.
- **Keyed on everything that decides its bytes.** `(corpus_sha256, event, store schema version, the hash of the source trees that decide what the store holds)`. The source trees are `shekyl-chain-store`, `shekyl-chain-rules`, `shekyl-chain-ingest`, `shekyl-archival-retention` and `Cargo.lock`. The corpus hash and the schema version alone are not enough: a fix to a fold under the same schema changes derived rows without changing either. The digest check above catches that anyway; the wider key keeps a stale entry from being served at all.
- **Consumed by copy, never written.** The helper copies the store file into the test's own temporary directory and opens the copy. The cached file is read-only to every consumer.
- **Where it lives.** CI: the Actions cache under the key above, built by a `chain-snapshots` job on a miss. Locally: under the build's target directory, keyed the same way. Never committed.

---

## 9. Regeneration

- **Same commit, same bytes (`CF-R2`).** `CF-1c`'s gate forges a small plan twice in CI and compares the outputs byte for byte; its selftest flips one byte of one output and asserts the gate goes red.
- **A consensus change regenerates in the same PR.** A pull request that changes any forged chain's bytes (any rule-07 consensus-boundary change, and anything else that moves a block) regenerates every affected chain in the same pull request. Its body names, per chain, the first differing block: the first line where the old and new `blocks.txt` differ (`shekyl-chain-forge diff`). The regeneration is a commit of its own, after the change that caused it.
- **How a PR finds out.** Forging Chain L takes too long for every pull request (measured in `CF-4`). The PR lane forges a **prefix** instead: the plan up to an early event that has already exercised every transaction kind once (named in `CF-4` from the catalogue), compared with the committed `blocks.txt` prefix. A mismatch is red with the instruction to regenerate. A change whose first effect lies past the prefix is caught by the nightly job.
- **Nightly.** A job regenerates every chain at `dev`'s HEAD and compares `blocks.txt`, `corpus_sha256` and `trace_sha256` (against the committed manifest for a small chain, the pin file for a hosted one). A difference without a regeneration having landed opens a `dev-red` issue through the workflow mechanism that already files them, naming the chain and the first differing block.
- **Nightly, the hosted copies** (`CF-R11`). A second nightly job pulls every digest in the pin file and re-checks every layer; a missing artifact or a mismatched layer opens a `dev-red` issue naming the chain and the digest (§10.4). It does not forge: the regeneration job above is the check on the bytes, this one is the check on the cache.
- **What a regeneration does not need.** No live daemon, no capture decision environment variable, no binaries built at a matching head (`regtest_e2e.rs`'s capture path, `CF-F11`): the forge is built at the commit it forges.

---

## 10. Storage

### 10.1 Measured, at `4b867a4f8`

| Corpus | Blocks | Transactions | `corpus.e2` (bytes) | `zstd -19` | `xz -9e` | `trace.e2` |
| --- | --- | --- | --- | --- | --- | --- |
| `spend-1in-2out` | 82 | 1 | 172,814 | 165,312 (−4.3 %) | 166,740 | 8,137 |
| `bond-post` | 109 | 2 | 205,313 | 193,766 (−5.6 %) | 196,176 | 16,687 |
| `limit-full` | 215 | 50 | 989,046 | 968,378 (−2.1 %) | 975,788 | 21,038 |
| `median-full` | 216 | 50 | 990,537 | 970,243 (−2.0 %) | 977,256 | 21,135 |
| `spend-depth3` | 762 | 1 | 1,161,496 | 1,106,503 (−4.7 %) | 1,117,308 | 74,097 |

Compression is not a lever: the line is stated on raw bytes. The history these five have left (`CF-F4`): about 2,050 blobs, 96 MB on disk, from about 20 re-captures since 2026-09-15.

### 10.2 Estimated

- **Chain L:** about 4,500 blocks (§4's slash estimate) × 1.5 KB of coinbase, plus two to three shard fills of about 227 spends each (3 MB of archival good per shard at about 13.2 KB a spend), plus the catalogue's other events (a few hundred transactions, two blocks at the weight bound): **15–25 MB**. Measured in `CF-4`.
- **Chain P:** 5,040 blocks × 30 two-in/two-out spends (the `PB-` design load, `DAEMON_REDB_STORE.md` §1.3a.1 rule 4) at about 20 KB each, plus the 4× stress segment: **about 3 GB before the stress segment**, several GB with it. Always hosted (§10.4).
- **Chain B:** about 3,600 blocks with two shard fills: **10–15 MB**.
- **The LWMA chain (W):** a few hundred blocks, mostly coinbase: under 1 MB. Committed.

### 10.3 The line

Ruling `CF-R3`: commit if possible, pin and host above a size line. Because the bytes do not compress or delta, the cost of committing is **size × regenerations**, paid in every clone forever. At the cadence the five corpora show (about 20 regenerations in two months, `CF-F4`), a committed 20 MB Chain L adds about 400 MB of history in two months, roughly doubling the repository's pack.

**The line (RULED 2026-11-12, `CF-R6`):** a chain's corpus bytes are committed when they are at most **5 MB** (today's footprint for all five corpora). Above it, the corpus is pinned by SHA-256 and hosted (§10.4). What shekyl-core commits for a hosted chain is its plan and `blocks.txt`, and the pin file; the corpus, the trace and the manifest are GHCR layers pinned by digest (`CF-R13`). Under that line, W is committed and L, B and P are hosted.

The KAT property (`CF-R2`) does not depend on where the corpus bytes live. `blocks.txt` is in the tree, and a regeneration's diff of it names the first differing block in the pull request itself. Because forging is deterministic, anyone can rebuild the corpus from the commit, so an unreachable artifact never blocks work: the fetch script falls back to forging.

**RULED 2026-11-12 (`CF-R6`).** The line stands as proposed. The hosted copy is a **cache**: deterministic regeneration at the pinned commit is the source of truth, so a missing or unreachable artifact is a slower path, never a broken one, and a deleted package is rebuilt, never lost. A disagreement between an artifact and a regeneration at its pinned commit is resolved for the regeneration (and is itself a determinism defect, `CF-R2`). The five old corpora move to this scheme when they are next regenerated: whichever change next regenerates one commits its `blocks.txt` and pins its layers, or commits the bytes if they are under the line (`CF-R13`).

### 10.4 Hosting: OCI artifacts on GHCR (RULED 2026-11-12, `CF-R11`)

- **Where.** `ghcr.io/shekyl-foundation/test-chains/<chain>`: one artifact per chain version (`…/chain-l`, `…/chain-b`, `…/chain-p`). The package is public once `CF-R14`'s approval is given, so CI and contributors pull without a token. It is linked to `Shekyl-Foundation/shekyl-test-chains`, which keeps the published manifests and release notes; the plans and `blocks.txt` stay in shekyl-core (`CF-R13`).
- **Content.** The chain's files are the artifact's layers, each with its own media type: `application/vnd.shekyl.corpus.v4` (the corpus, layout 4, §7.1), `application/vnd.shekyl.trace` (the trace) and `application/vnd.shekyl.manifest+json` (the manifest, format 5, §7.2). The artifact type is `application/vnd.shekyl.test-chain`. A layout or format change bumps the media type with the version constant (rule 42's discipline applied to the artifact).
- **Pinned by digest, never by tag.** shekyl-core commits a **pin file** (created with the first hosted chain, in `CF-4`), recording for each chain its name, its version, the OCI manifest digest (`sha256:…`), and each layer's SHA-256 and size. Tags such as `chain-l:cf4-2026-11-xx` are labels for people only: a tag can move, a digest cannot, so nothing in shekyl-core reads a tag.
- **Fetch.** The fetch script runs `oras pull ghcr.io/shekyl-foundation/test-chains/<chain>@sha256:<digest>`, re-checks every pulled layer's SHA-256 and size against the pin file, and refuses on any mismatch, printing both values. On a missing artifact it says so and gives the forge command that rebuilds the chain at the pinned commit. In CI, `actions/cache` is keyed on the digest, so each runner pulls a chain once.
- **`oras` is now part of the supply chain** (rule 17). It is installed from a pinned release, and its checksum is verified against a value committed beside the install step before it runs. A changed checksum is red, never re-pinned in passing.
- **Publish only through review.** Only a workflow in `shekyl-test-chains` pushes: it has `packages: write`, runs in a protected environment that needs Rick's approval, pushes the artifact and prints its digest. No personal token pushes. The forge PR in shekyl-core then updates the pin file with that digest, so **a pin change is always a reviewed core PR**. The forge lane opens that PR; the approval of the publishing run is Rick's.
- **The repository and the package (`CF-R14`).** `shekyl-test-chains` is public: the organization is on GitHub's free plan, where an environment's required reviewer works only in a public repository. Its `main` takes changes only through a pull request and refuses deletion and force-pushes, with no bypass. The `publish` environment requires Rick's approval and deploys only from `main`. The workflow token is read-only unless a job asks for more, workflows from outside contributors' forks wait for approval, and only GitHub-owned actions pinned to a full commit SHA may run (the publishing workflow needs `actions/checkout` and `actions/cache`; `oras` comes from its checksum-verified release, not an action). **The package stays private until `CF-4`'s first artifact has been reviewed,** and is made public only on Rick's explicit approval, because a public package cannot be made private again. Rick checks the organization's public-package setting by hand before `CF-4`.
- **Small chains stay committed** (`CF-R6`): a chain whose bytes are 5 MB or less lives in shekyl-core and has no artifact.
- **Noticed the next day.** A nightly job pulls every digest in the pin file and fails, through the existing `dev-red` mechanism, if any is missing or any layer disagrees with its pin. A deleted or damaged artifact is then noticed the day after, not at the next test that needs it (§9).

---

## 11. The forge

### 11.1 Shape: a library, a test-kind runnable, no binary (`CF-F2`)

`rust/shekyl-chain-forge` holds:

- **The library** — the plan schema (TOML through `serde`), the seed derivation (§5.1), the manifest-5 and `blocks.txt` reader and writer, and the diff. It has **no** normal-edge dependency on the scenario driver, the harness spender, or any seed seam. A crate that only reads manifests (the snapshot helper, a consumer's test) takes this library alone.
- **The executor and its runnable** — an `[[example]]` target (`cargo run -p shekyl-chain-forge --example forge -- --plan <file> --out <dir>`), whose driver, spender and seed-seam edges are `[dev-dependencies]` of the forge crate. Cargo builds an example with the dev-dependencies and builds it only when asked for examples or tests; the release build (`cmake/BuildRust.cmake`) never asks.
- **The determinism gate** — an ordinary integration test of the same crate (`CF-1c`): forge the small plan twice, in two processes, compare.

**Where the executor's code lives.** Library code cannot use `[dev-dependencies]`, and an integration test cannot import an example's modules. So the executor is a module tree outside `src/` (`rust/shekyl-chain-forge/executor/`), included by both test-kind targets (`examples/forge.rs` and `tests/determinism.rs`) with `#[path]`, the way a crate's tests share `tests/common/`. Both targets compile it against the dev-dependencies, and the library never sees it.

**Why not a binary.** A `[[bin]]` builds against `[dependencies]` only, so it would reach the driver and the seeds through normal edges, and the test-only gate refuses that by design (limb 1). Widening the gate to admit "a binary nobody ships" would trade a mechanical property (no normal edge enables a test-only feature) for a list someone keeps. The example target keeps the property and costs the user one word (`--example`). RULED (`CF-R8`): a cargo example is fine. **CI must build the examples:** `CF-1c` adds a step that runs `cargo build --examples` over the workspace in the Rust job, beside the `--all-targets` clippy that checks but does not link them, so an example that stops linking is red on the pull request that broke it.

**Proved absent from every shipped graph, not asserted.** Three checks, all in CI from `CF-1b` (the graph check gains the forge crate in `CF-1c`):

1. `check_test_only_features.py` rows for every new feature (§5.3), with `CF-F5`'s forwarding fix, so each is enabled on dev edges only.
2. The production graph check, in the shape of `check_p_fetch_dep_cut.py`: over `shekyld`, `shekyl-cli` and `shekyl-wallet-rpc`'s normal and build edges, no `shekyl-chain-forge`, no `shekyl-harness-spender`, no `shekyl-harness-wallet` and none of §5.3's features. It asserts its own subject (rule 47): the three binaries exist and their graphs are non-empty.
3. The production-shape lint lane (`rust-audit-test.yml`'s `--lib` clippy over the TEST_ONLY owners) gains the new owners, as the gate's own docs require.

### 11.2 The plan

A plan is a list of steps by phase, each a call the executor already has a production path for. An illustrative fragment:

```toml
chain = "L"
seed = "<64 hex>"
network = "regtest"
fixed_difficulty = 1
schedule = { settlement_epoch_blocks = "settled", reorg_cap_blocks = 10 }

[[step]]
event = "first-spend-1in-2out"
do = "spend"
shape = { inputs = 1, outputs = 2 }

[[step]]
do = "fill-shards"
count = 1

[[step]]
event = "first-compact-join"
do = "join"
persona = 0
holdings = { compact = [0] }

[[step]]
event = "reorg-shallow"
do = "fork"
depth = 2
alt_spends = 1
```

A lane needing a new feature adds a step kind to the executor and a step to the plan, not a bespoke harness. Schedule values that are derived, not written (`"settled"` is `settled_epoch_blocks()`), stay derived: the plan names the derivation and the manifest records the number it produced.

### 11.3 The run

The executor builds each block the way the scenario driver does today: the connector's template facts, the production template, `form`, `validate` and `connect` against a real store (`scenario.rs:261–315`). It writes each block to the corpus as it lands, and each competing block as an `offer`. The trace is then produced **from the written corpus** by the same code `shekyl-chain-replay baseline` runs (`rebaseline`), on a fresh store. So the trace is the production pipeline's verdict on the bytes on disk, independent of the forge's own run: a forge that wrote different bytes from the ones it connected fails there.

**The substrate while forging.** L, B and P are fixed difficulty 1, where any longhash satisfies the target (`scenario.rs:141–143`), and the proof-of-work hash is not part of a block's bytes. So the forge builds them over the free longhash (`FreeHash`) and spends no time on RandomX; the trace's replay then verifies every block with real RandomX. W is the exception (§4): it is forged over the production substrate, because its nonces must satisfy a live target.

---

## 12. Increments, and the consumer tracking table

### 12.1 Increments (one PR each)

- **CF-0 — this document** (moved from `docs/CANONICAL_CHAINS.md`), the `CF-` index rows and the decision-log entry. Design only: no code.
- **CF-1a — chain identity** (`CF-R10`, `CF-R15`; §6). **BUILT (as of 2026-11-13, #1370).** Adds a regtest mode alongside the existing harness id; §6 governs. In that mode the scenario driver runs pinned to regtest's table genesis, connecting it as block 0; the spender signs under regtest's network id; personas and the miner derive under regtest's name. The identity test's four locks on a driver-built chain, lock 4 by citation of the transport's prefix test. The harness id and `Persona::at`'s mainnet derivation stay for the chains that mine their own genesis, marked test-only and due for deletion in `CF-5`. As built:
  - **The driver.** `Scenario::open_regtest` connects the table genesis through `Scenario::offer_genesis`, the form and apply a mined block takes; `shekyl-genesis-tool`'s `genesis_block` assembles it as the node does.
  - **The miner.** `MinerWallet::harness_regtest` is `account_from_seed(HARNESS_SEED, Regtest)`, its secrets copied into fields that wipe on drop.
  - **The ids.** `Spender::on` builds a spender for a network, and every `Sourced` output carries the id; the emission assembly takes a `ClaimAnchor`, the id and the proof reference together; the driver's bundles use `Scenario::network_id`; personas derive with `Persona::on`.
  - **The tests.** The identity test is `shekyl-chain-ingest` `scenario::scenario_identity_tests::a_regtest_chain_never_validates_as_another_network`. Lock 3's proof leg is `shekyl-chain-rules`' `judge_claimed_proof`, a harness item. Lock 4 is `shekyl-clearnet` `tests::a_listener_refuses_every_other_networks_prefix_and_takes_its_own`, and the public seed's refusal `shekyl-harness-wallet` `tests::the_regtest_miners_address_is_refused_off_regtest`.
- **CF-1b — the RNG line** (`CF-R9`, `CF-R10`; §5.3–§5.5). `CF-F5`'s forwarded-feature gate fix and its selftest; the seams T1–T4 under `seeded-rng`; `prove_with_rng` crate-private behind it, `shekyl-verify-cost` enabling it (`CF-F12`); `shekyl-crypto-pq` into `GOVERNED_OWNERS` through F-7; the harness id behind a `TEST_ONLY` `harness` feature on `shekyl-network`, which `CF-F5`'s forward fix is what lets the gate hold (`shekyl-chain-rules`' `harness` forwards it), with `Spender::over` gone and its callers passing the chain's own id (`CF-R15`); the seedable-RNG gate and its site list, every current hit listed or changed (§5.5, `CF-R12`), with the SAL multisig's two conditions (the `y`-nonce test and the recorded transcript-binding line); the production graph check (§11.1).
- **CF-1c — the forge skeleton and the determinism CI check** (`CF-R10`). `shekyl-chain-forge` (the library and the `forge` example, with CI building the examples, `CF-R8`); T5's `forge` feature on the driver; the plan runner; every source in §5.2 routed through the plan's seed; the audit items of §5.2; the identity test on the small plan; the twice-forged determinism check in CI and its selftest, on x86_64 and aarch64; Chain B's producer audit (§4).
- **CF-2 — a real serve-credit countersigner** in the harness spender, built to the serve-credit spec, replacing `[0x5c; 64]` (`CF-F6`), with the verifier accepting it and refusing a tampered one. First question: whether `shekyl-p-host`'s pass signer already signs the vin's object. The store tests on padded credits are listed in §12.2 for migration, not migrated here.
- **CF-3 — corpus layout 4** with `offer` (§7.1); `shekyl-chain-replay` and the replay tests read it; one shallow reorg forged and replayed, its switch derived and held equal to the manifest's.
- **CF-4 — Chain L v1** with every event available now (§3), its manifest and ledger, the snapshot job (§8), the PR-prefix and nightly regeneration checks (§9); the hosting (§10.4): the pin file, the fetch script, `oras` pinned and checksum-verified, the digest-keyed CI cache and the nightly pull check. The publishing workflow lives in `shekyl-test-chains` (created and configured, `CF-R14`), and its first run waits on Rick's approval; the package is made public only after that first artifact is reviewed, on his explicit approval. **Pilot consumers in the same PR:** #1360's emission-claim bench row (its setup opens the `first-settled-epoch` snapshot) and one nightly shard-refill test switched to a snapshot, with its time before and after. **Report:** blocks, transactions, raw size, forge time on a workstation, snapshot build time on CI.
- **CF-5 — consumer migration**, per lane, tracked in §12.2. The forge lane migrates the corpus replay tests, the chain-sync loopback and `archival_sufficiency_tests` (making its unwitnessed families witnessed); every other lane migrates its own. The five old corpora are deleted when their last consumer has moved. The harness id (`HARNESS_NETWORK_ID`) and `Persona::at`'s mainnet derivation are deleted here (`CF-R15`). The id is what `Trust::UNPINNED` judges a chain that mines its own genesis under, so its deletion takes `Trust::UNPINNED` and `GenesisPin::NONE` with it, and every such chain is held to a genesis first: regtest's table genesis, or a fixture's own block 0 pinned with its id derived from that block (`NI-R10`'s derivation, applied to a test genesis). At `bb50048b4` that is 160 uses of `Trust::UNPINNED` in 60 files, most of them the rules crate's own fixtures (26 files), chain sync's (17) and the store's (9), beyond the driver's chains. Those are owned by their lanes, so §12.2 tracks them with the rest.
- **CF-6 — Chain P and the LWMA chain,** with the daemon budget lane: the production schedule at 30 transactions a block for 5,040 blocks plus a 4× segment; the chain hosted on GHCR and pinned (§10.4); `drs_catchup`, `drs_bench`, `drs_crash` and `drs_powerloss` pointed at it. The LWMA chain under live difficulty with spaced timestamps, committed.
- **Later — stress mode** (not yet an increment): the forge's plans drive a live seed node for initial sync and catch-up, and its adversarial profiles (blocks at the weight bound, slash storms, withheld blocks) become `PB-D1`'s shape set (`DAEMON_REDB_STORE.md` §1.3a.7).

**The lane's first milestone (`CF-0`…`CF-4`):** Chain L exists, is committed or pinned, regenerates byte for byte, carries every event available today, and two real consumers read it through snapshots.

### 12.2 Consumer tracking

One row per consumer group, from the census at `4b867a4f8`. **Status** is NOT STARTED for every row at `CF-0`; a migrating PR updates its row (rule 94 §4's shape: current status and date first). "Forge lane" rows are `CF-5`'s; every other row is its lane's (`CF-R5`). Paths are under `rust/shekyl-chain-ingest/src/` unless given in full.

| Consumers | Today's chain | Lane | Target | Status |
| --- | --- | --- | --- | --- |
| `vectors_tests.rs:153`, `:406`, `:705`, `:747`; `vectors_tests/rebaseline.rs:61`, `corpus_census.rs:103`, `pool_door.rs:35`, `relay_floor.rs:45`, `too_many_inputs.rs:57`, `h19_cost.rs:43` | the five corpora | forge lane (`CF-5`) | L, all of it | NOT STARTED |
| `header_path_tests.rs` (9 tests: `:210`…`:1029`); `sync_wire_tests.rs:41`, `:77` | the five corpora | forge lane (`CF-5`) | L | NOT STARTED |
| `archival_corpus_tests.rs:212`; `archival_sufficiency_tests.rs:240`, `:315`, `:372` (unwitnessed families become witnessed) | the five corpora | forge lane (`CF-5`) | L, CF-E12…E17 | NOT STARTED |
| `rpc_store_facts_tests/mod.rs:685` | the five corpora | DRS | L | NOT STARTED |
| The chain-sync loopback (`shekyl-p2p-harness/tests/chain_sync_loopback.rs`, `_claim_relay.rs`, `_cutover.rs`, `_opening.rs`: 31 tests through `chain_sync/support.rs:265`); `shekyl-chain-sync/src/scenarios.rs:88` | `spend-1in-2out` | forge lane (`CF-5`) | L to CF-E1, CF-E22 for the fork tests | NOT STARTED |
| `cs2-long-run` (`shekyl-p2p-harness/tests/chain_sync_long_run.rs:103`, `:172`) | the five corpora; never run | chain sync | L, then P | NOT STARTED |
| The nightly fills: `archival_pop_roundtrip_tests.rs:88`, `:182`, `:311`; `archival_slash_tests.rs:691`; `scenario_emission_tests.rs:125`, `:628`; `scenario_join_tests.rs:67`; `pool_submit_tests.rs:305`, `:378`; `rpc_store_facts_tests/below_horizon.rs:130` | the driver plus a fill, each | DRS, ARCH, SO-D12, DRS-SB (one row each in `CF-5`) | L snapshots at CF-E10…E21; one of them is `CF-4`'s pilot | NOT STARTED |
| `shekyl-chain-store/src/store/prune_tests.rs:825` | 54 real 8-input spends | DRS | L snapshot at CF-E10 | NOT STARTED |
| The 18 padded-credit tests in `prune_tests.rs` (`sized_credit`) | padded credits on a grown chain | DRS | L snapshot at CF-E12 | NOT STARTED |
| `shekyl-chain-store` grown-chain tests with real joins (`archival_write_tests.rs`, `block_draws_write_tests.rs`, `support_seats_chain_tests.rs`, `admission_chain_tests.rs`, `store/alt_tests.rs:670`, `verify_site_tests.rs:28`, `output_read_tests.rs:227`) | grown chains | DRS | L snapshots, where the test's subject is the chain rather than the builder | NOT STARTED |
| `bundle_producer_gate_tests.rs:333`, `:549` | the producer's own chain | SO-D12 | B, if forgeable (§4) | NOT STARTED |
| The seed-boundary tests: `service_tests.rs:615`, `:2994`; `service_seed_tests.rs:490` | the driver, 2,114+ blocks | DRS | L at CF-E7 | NOT STARTED |
| `switch_timing_tests.rs:165`, `:171`, `:180`, `:186` | two drivers at the production cap | DRS | P at CF-E31 | NOT STARTED |
| `miner_tests.rs:425` (LWMA) | real mining | economics | W | NOT STARTED |
| #1360's emission-claim bench row | none yet | benches | L snapshot at CF-E13; `CF-4`'s pilot | NOT STARTED |
| `regtest_e2e.rs` capture generators (`:1933`, `:2373`, `:2685`, `:2983`, `:4168`) | live daemon | forge lane (`CF-5`) | stop capturing; keep the walk as a live-daemon test | NOT STARTED |
| `regtest_e2e.rs:4303` (emission claim, DECIDED_DARK) | live daemon | SO-D12 | stays a live-daemon walk; its corpus role passes to L | NOT STARTED |
| The `ct2_tier_a`/`ct2_tier_b` fixtures (`shekyl-curve-tree/tests/recon_*.rs` and their readers) | generated from a live daemon | curve tree | L at CF-E6 and CF-E26 | NOT STARTED |
| `scripts/bench/drs_catchup.py`, `drs_crash.py`, `drs_powerloss.py`, `drs_bench.py` | coinbase-only or refused | daemon budget | P | NOT STARTED |
| The open-edge bench (`wss_q1b_regtest_open_edge.sh`, `docs/FOLLOWUPS.md:1375`) | coinbase-only | wallet | P | NOT STARTED |
| Every chain judged under `Trust::UNPINNED` (160 uses in 60 files at `bb50048b4`: `shekyl-chain-rules` 26, `shekyl-chain-sync` 17, `shekyl-chain-store` 9, `shekyl-chain-ingest` 3, `shekyl-mempool` 2, `shekyl-block-template`, `shekyl-harness-spender` and `shekyl-network` 1 each), and every `Spender::over` caller | mines its own genesis, signs under the harness id | each crate's lane; the driver's and the spender's are the forge lane's | held to a genesis (§12.1 `CF-5`); then the harness id is deleted (`CF-R15`) | NOT STARTED |

The PR-lane driver tests that build a few blocks with a few real spends (about 120, in `scenario_spend_tests.rs`, the pool and switch suites, `rpc_store_reads_tests.rs` and others) are not rows. Their subject is a step the driver takes, not a chain, and a few blocks cost seconds. A lane that finds one reading a long prefix moves it to a snapshot and adds a row.

---

## 13. Questions for Rick — all RULED 2026-11-12

`CF-Q1`…`CF-Q5` were put to Rick in `CF-0` and ruled the same day; the rulings are `CF-R6`…`CF-R9` and `CF-R13` (§1). The questions as asked are in this document's history.

- **CF-Q1 — the storage line.** RULED: `CF-R6`.
- **CF-Q2 — reading two corpus layouts during migration.** RULED: `CF-R7`.
- **CF-Q3 — the forge's runnable as an example target.** RULED: `CF-R8`.
- **CF-Q4 — where the no-injectable-RNG line is held.** RULED: `CF-R9`.
- **CF-Q5 — which repository holds a hosted chain's plan, manifest, `blocks.txt` and trace.** RULED: `CF-R13`.
