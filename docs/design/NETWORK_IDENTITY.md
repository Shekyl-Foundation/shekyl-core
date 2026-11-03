# Network identity — one pathway for every network: Round 0 (`NI-`)

**Families (registered in `IMPLEMENTATION_INDEX.md` §2, rule 94):** **`NI-R`** (rulings), **`NI-Q`** (questions) and **`NI-F`** (findings). `NI-` is free at `8f2b68dbbf`.
**Ground:** `feat/drs-s1-no-checkpoints` at `8f2b68dbbf` (#1263, 2026-11-03), read from the tree. The design review's first draft read `dev` at `b8f1b76c0`; the two places this ground differs from that draft are NI-F1 and NI-F2.
**Status:** OPEN — Round 0. NI-R1…NI-R11 RULED by Rick 2026-11-03 (NI-R6 rules NI-Q11, NI-R7 NI-Q12, NI-R8 and NI-R9 NI-F7, NI-R10 NI-F9, NI-R11 NI-F10); NI-Q10's shape RULED the same day (§3). NI-Q1…NI-Q9 are building as recommended, in §8's order. Mainnet's row is PROVISIONAL until the genesis ceremony (NI-R11). Each row of §5 carries its own status.
**Related:** [`FCMP_SPEND_SIGNING_PREIMAGE.md`](FCMP_SPEND_SIGNING_PREIMAGE.md) (NI-Q4), [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) (NI-Q9), [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) (the genesis content), rule [`71-network-uniformity`](../../.cursor/rules/71-network-uniformity.mdc).

---

## 0. Purpose

A network is its genesis block. Every network — mainnet, testnet, stagenet and regtest — is built by the same tool, through the same code path, and differs from the others only as **data** in one table. Nothing branches on which network it is; nothing treats one network as another. Identity says **which chain**; compatibility (NI-Q10) says **whether two builds agree on what a valid block is**, and the two are never used for each other.

This replaces a set of mechanisms that each half-identified a network and disagreed about regtest:

| Layer | Identity at this ground | Where |
| --- | --- | --- |
| Genesis | `GENESIS_TX` + `GENESIS_NONCE` per network as C++ header text (`src/cryptonote_config.h`, nonces 10000 / 10102 / 10002), read by no C++ in `src/`: Rust parses the header (`shekyl-node/src/genesis.rs`, `shekyl-genesis-tool/src/config_pin.rs`; NI-F4). Block-hash pins again in `genesis_hash_for` (`shekyl-rpc-types/src/identity.rs`) and `GenesisPin` (`shekyl-chain-rules/src/genesis_pin.rs`). Regtest (`FAKECHAIN`) takes mainnet's genesis. | one value, several copies |
| P2P network id | `cSHAKE256("shekyl/p2p-network-id-v1", genesis)[..16]` (`shekyl-p2p-transport/src/prefix.rs`); regtest's equals mainnet's, and the C++ handshake sends it (`get_config(FAKECHAIN)` returns mainnet's config; `src/p2p/net_node.inl`) | derived from genesis; regtest aliased |
| Clearnet wire prefix | derived from the network id | derived |
| Noise handshake | the prologue is the network id (`shekyl-p2p-transport/src/noise.rs`, NI-F1) | derived; no wire version |
| Data-dir marker | records the network id (`shekyl-daemon-config/src/marker.rs`) | derived, but a file beside the store |
| Chain store and validator | `GenesisPin` at the read-only open (#1263); on regtest the store pins mainnet's genesis while `validate` runs unpinned (NI-F3) | block 0; regtest read three ways |
| Pool file | nothing | not bound |
| Transaction signing | `payload(i)` (`shekyl-wire/src/transaction/signing_preimage.rs`) carries no network | not bound |
| Message signing | binds `DerivationNetwork::as_u8`, an enum code (NI-F2) | bound to a code, not the derived id |
| RPC identity | `accept_fakechain` / `exact_or_fakechain` carve-outs (`identity.rs`) | regtest special-cased |
| Addresses | `shekyl_address::Network` has no regtest; regtest takes mainnet's prefixes | regtest aliased |
| Network types | five enums (`shekyl_daemon_config::Network`, `shekyl_rpc_types::DaemonNetwork`, `shekyl_address::Network`, `shekyl_crypto_pq::DerivationNetwork`, `shekyl_dialer::SeedNetwork`), plus `CorpusNet` and `Chain` in `shekyl-chain-ingest` and C++ `cryptonote::network_type`; six numeric encodings (NI-F5); two names for one network (`regtest` in the operator grammar, `fakechain` on the RPC wire) | one concept, many spellings |

## 1. The nonce

The block nonce is a proof-of-work field. The genesis block isn't mined, so its nonce carries no work; CryptoNote used it to give two networks different genesis hashes from the same genesis transaction, and Monero inherited that. It is an identity mechanism sitting in a work field. The genesis tool already writes the coinbase-extra nonce as eight zero bytes "because genesis was not nonce-searched, and zero says so" (`shekyl-genesis-tool/src/builder.rs`), while the C++ header nonce is the discriminator.

**Rule (NI-Q1):** the genesis header nonce is `0` on every network. Identity comes from the genesis **content**. The nonce field stays in the header for mined blocks, where it means something.

## 2. The design

### 2.1 A network is its genesis block

The **chain id** is the genesis block hash. The 16-byte **network id** is `cSHAKE256(NETWORK_ID_DST, genesis)[..16]`. It is self-certifying: no registry, no numbering, nothing to coordinate. Ethereum's small-integer chain id needs a registry; Polkadot's genesis-hash binding and Bitcoin's per-network magic are the equivalents of this.

### 2.2 Genesis content makes networks distinct, visibly (NI-Q2)

Each network's genesis is built by the genesis tool from its own definition:

- its own **recipients file** (`config/genesis_recipients.<network>.json`); regtest's carries a committed deterministic test recipient whose key is published and marked test-only;
- its own **genesis transaction key**;
- a **network tag in the coinbase extra**, `shekyl/<network>`, the same shape on every network, with no cut or generation field. Two networks can't collide even with identical recipients, and anyone reading a genesis can say which network it is.

Regtest then shares **no state** with mainnet: no output, no curve-tree leaf, no root.

### 2.3 One genesis table, in Rust (NI-Q3)

One crate holds one table: `network → { name, genesis block bytes, genesis hash, address prefixes, rule set, seeds, ports, difficulty parameters }`, and one network type. Everything reads it:

- `genesis_hash_for`, `GenesisPin`, `network_id_from_genesis`, the wire prefix, the marker, the RPC identity, the address codec, wallet derivation, seeds;
- the remaining C++ through the FFI it already uses for the network id (`shekyl_network_id`), never a copy of its own. `cryptonote_config.h`'s `GENESIS_TX` / `GENESIS_NONCE` are deleted: no C++ in `src/` reads them (NI-F4).

**Tests that hold it, over all four networks:** (a) each network's genesis block, rebuilt from its definition by the genesis tool, hashes to the pinned hash; (b) every network's genesis hash, network id, wire prefix and address-prefix set are pairwise distinct; (c) each genesis's coinbase extra carries its own network tag.

### 2.4 Bind the identity wherever cross-network confusion could matter

- **Transaction signing (NI-Q4).** `payload(i)` gains the network id through a cSHAKE customization. A signature is then valid on exactly one network by construction, not because tree roots happen to differ. It changes the KAT and [`FCMP_SPEND_SIGNING_PREIMAGE.md`](FCMP_SPEND_SIGNING_PREIMAGE.md) §1.1, and every signer (`shekyl-tx-builder`) and verifier (CEN-I17) in one change.
- **Noise prologue (NI-Q5).** The prologue is `network id ‖ wire-protocol version`. The network id is already there (NI-F1); the wire version joins it.
- **Pool file (NI-Q6).** Its seal records the network id. The chain store needs no field: it has block 0.
- **Marker file (NI-Q7).** A derived label for humans and tooling; nothing trusts it for identity, because every holder of chain data checks the genesis-derived id itself.
- **Every other domain (NI-Q9).** Audit [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv): every signature or commitment that could be replayed across networks binds the network id, or is shown unable to replay.

### 2.5 Regtest is a network, not an exception (NI-Q8)

Regtest is a row in the table: its own genesis, address prefixes, ports, difficulty parameters and permitted levers (NI-Q11). It has one name, `regtest`, everywhere: the operator grammar, the RPC wire's `nettype`, the C++ `network_type`, the derivation salt and the corpus tag; `fakechain` goes (rule 83: no aliases). The `accept_fakechain` carve-outs, `GenesisPin::FAKECHAIN`, the `Fakechain → Mainnet` address and port mappings, and every "fakechain shares mainnet's" comment go. The E2 corpus's regtest chains re-capture under the new genesis through #1244's capture path.

## 3. Compatibility at the handshake, not by rotation (NI-Q10) — SHAPE RULED 2026-11-03

**The hazard.** Two builds with incompatible rules that share a network id connect, reject each other's blocks, and ban each other. Rotating a test network's genesis stops them connecting, but it uses identity to solve a compatibility problem. NI-R5 rules rotation out.

**The mechanism.** Message one's **encrypted payload** carries each side's rule schedule, as `(activation height, rules digest)` steps, **and its tip height**. The receiver compares every step at or below the **higher** of the two tips; a disagreement is refused with a reason: no connection, no block exchange, no ban. This is the same shape as RPC's `get_version.consensus_constants_digest`, where a wallet refuses a daemon whose digest differs.

- **Symmetric.** A fresh node at height 100 facing an old build at 10,000 that lacks the step at 5,000 compares up to 10,000, so it refuses the old build too.
- **A lying tip buys a refusal.** Claiming a higher tip only widens the range compared.
- **Not-yet-activated steps don't refuse.** A peer that lacks a future step connects until that step activates, so a scheduled upgrade has an upgrade window instead of a split at release.
- **Nothing tip-dependent goes in the prologue**, and no whole-schedule digest either, even as a fast path: the prologue holds only what both sides already share, and a schedule digest there would refuse every not-yet-upgraded peer the moment a new build ships.

**Consequences.** A network's genesis is fixed for its life. A pre-genesis consensus change on a test network restarts the chain from the **same** genesis, and old builds are refused at the handshake until they upgrade; the alpha wipe handles their stores. Mainnet works the same way. The frozen-tuple release gate (`scripts/release/check_frozen_tuple.py`), whose remedy is a nonce rotation, shrinks to what `PINNED_DIGEST` already enforces at build time, or is deleted, in the NI-Q10 PR.

## 4. Rulings

- **NI-R1 — RULED 2026-11-03: regtest gets its own address prefixes.** Every chain is treated equally, so any accepted chain exercises the mainnet pathway. Regtest is a network like the others. Closes FOLLOWUPS row 7 / RD-Q7.
- **NI-R2 — RULED 2026-11-03: the signing domain binds the network id only, not the rule set in force.** Reasoning below.
- **NI-R3 — RULED 2026-11-03: this is a round, not a PR.** It touches consensus (signing), the wire (the handshake), the store, the corpus and the C++ genesis constants, and should land once.
- **NI-R4 — RULED 2026-11-03: one pathway for every network, no exemptions.** All four networks get a tool-built genesis with nonce 0 and the network tag. Testnet and stagenet regenesis once, in this round. Both nonce fields stay: the header nonce for proof of work and the coinbase-extra nonce for pooled mining. Genesis writes zero in both, and neither identifies a network.
- **NI-R5 — RULED 2026-11-03: no genesis rotation, ever.** Compatibility is NI-Q10's handshake check, not a regenesis.
- **NI-R6 — RULED 2026-11-03 (NI-Q11): regtest's levers are a `permits` field on the network's row.** One gate reads it, the existing armed-lever gate, answering from the row; the scattered "is regtest" and "is the trust unpinned" checks go (NI-F3). The field is compiled into the table, never configurable. Invariant test: `permits` is empty on every row but regtest's. Its entries include the inject-serve-credit and issue-draws writes, which the archival corpus chains replay through (NI-F6), and `dev-rpc` (NI-R8).
- **NI-R7 — RULED 2026-11-03 (NI-Q12): one seed format on every network: BIP39, 24 words only.** No 12-word option, not even on import: 128 bits is 64 bits of quantum security under Grover, below Shekyl's post-quantum floor. No BIP39 passphrase: its PBKDF2 stretch is weak, and the wallet file has its own encryption. Derivation takes the 32 entropy bytes the words encode, not BIP39's PBKDF2 output. **One secret, one derivation (NI-F8):** words and raw hex are two spellings of the same 32 bytes and yield the same wallet, so the seed format leaves the derivation salt and the wallet file's authenticated data. The network stays in the derivation, as the network's name (NI-R10), so the same 32 bytes on two networks give unrelated keys. Every key-derivation vector is re-recorded, mainnet's included; the wallet-file change rides regtest's address-byte version bump (NI-F5). Raw32 survives only as harness input where a fixture injects a fixed key, the genesis tool's recipient wallets included.
- **NI-R8 — RULED 2026-11-03 (NI-F7): `dev-rpc` is regtest-only.** `generateblocks` on a real-difficulty network is `start_mining`; it is a shortcut only where difficulty is fixed. `pop_blocks` leaves the RPC entirely and becomes "rewind N blocks" in the S3 operator store tools, on every network including mainnet, beside "move aside and rebuild". Until that tool lands, `pop_blocks` is a regtest `dev-rpc` lever like `generateblocks`; it leaves the RPC in the change that ships its replacement.
- **NI-R9 — RULED 2026-11-03 (NI-F7): staging is a named class, separate from `permits`.** A staging flag stages a candidate mainnet behaviour on the test networks; it is not a test-only shortcut. Every staging flag names its owner and its exit (promoted to default behaviour, or deleted); it is accepted on the test networks only; **no staging flag survives mainnet genesis**, held by an invariant test at the genesis cut. Members at this ground: `dev-clearnet-encrypt` (owner: the Noise flip; exit: deleted at the flip) and `dev-relay-cover` (owner: the cover-traffic lane, TRC-1; exit: its outcome). The class gives a future rollout a sanctioned route without bending the one-pathway rule.
- **NI-R10 — RULED 2026-11-03 (NI-F9): the network has two forms, a name and an id.** The **name** is the root: the static tag `shekyl/<network>`, compiled into the table, used wherever genesis can't exist yet: key derivation, address prefixes, and the genesis coinbase, which carries it. The **id** is derived, `cSHAKE256(NETWORK_ID_DST, genesis hash)[..16]`, used everywhere after genesis exists: the handshake and wire prefix, the store pin, the pool seal, and transaction and message signing (NI-Q4, NI-Q9). The two are bound one-to-one: genesis commits to the name in its coinbase, so the id commits to the name. Invariant tests: every row's genesis coinbase carries that row's name, and names are pairwise distinct.
- **NI-R11 — RULED 2026-11-03 (NI-F10): the test networks' recipients are regenerated in PR 1; mainnet's at the genesis ceremony.** Testnet, stagenet and regtest use test recipients and test keys, regenerated in PR 1 under the new derivation, pins included. Mainnet's custodians keep their seeds; only the addresses derived from them move, because the salt changed. They re-derive with the new tool and deliver new recipients files, each confirming their own address: a ceremony with real people and real seeds, not on a PR's clock. Mainnet's row lands in PR 1 marked PROVISIONAL, with the tool path ready, and is pinned the same way as the test networks once the files are back; mainnet's genesis isn't final, so nothing ships on a provisional pin. A custodian holding a raw 32-byte seed is shown the 24 words for the same bytes; under NI-R7 that is the same secret, so no key changes.

### 4.1 NI-R2: why Zcash binds the rule set, and why Shekyl doesn't

**What Zcash does.** Since ZIP-143 the sighash is domain-separated by the *consensus branch id* of the network upgrade the transaction is valid under: (1) replay protection across a chain split, where both sides share genesis; (2) upgrade safety, so a transaction signed under old rules is invalid after activation.

**It isn't maintainer control.** A scheduled rule set is already consensus; binding its id lets the *signer* state which rules they intended. So "no" can't rest on that ground.

**Why no, on the real grounds:**

- **The benefit is for a chain split, and it belongs to the side that splits.** The network-id binding already separates networks. A branch id adds separation between two chains sharing a genesis, which only exists after a contentious fork. Bitcoin Cash added its own `SIGHASH_FORKID` when it forked; the base chain needn't pre-build it. Pre-building makes the rule schedule something every signature depends on, forever.
- **The cost lands on every wallet at every upgrade.** A signature bound to a rule set dies the block the next one activates; every unincluded transaction is re-signed, slow and large under hybrid Ed25519 + ML-DSA, and a multisig container at maximum signers needs a fresh ceremony. Wallets would also need the rule set in force at inclusion, not just at signing.
- **It leaks a timing bit:** which rule window a transaction was signed in.
- **Signature size doesn't decide it.** Both options are preimage domain separation.

**If a split ever happens,** the forking side changes its signing customization (one line in NI-Q4's domain) and its network-id derivation. The mechanism is available then.

## 5. Questions

| Q | Question | Status |
| --- | --- | --- |
| NI-Q1 | The genesis header nonce. | BUILDING (PR 1): `0` on every network; identity from content (§1). |
| NI-Q2 | What the genesis content carries. | BUILDING (PR 1): recipients, tx key, and the tag `shekyl/<network>`, the same shape on every network; regtest's recipient and key committed and marked test-only (§2.2). |
| NI-Q3 | The one Rust table: fields, readers, the network type; the C++ genesis constants. | BUILDING (PR 1): §2.3; the C++ genesis constants deleted outright (NI-F4); one network type with one code (NI-F5); tests (a)–(c) over all four networks. |
| NI-Q4 | The signing domain. | OPEN (PR 2): a cSHAKE customization carrying the network id; signer, verifier (CEN-I17) and KAT in one PR; `FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1. |
| NI-Q5 | The Noise prologue. | OPEN (PR 3): `network id ‖ wire-protocol version`; the network id is already the prologue (NI-F1), so the change is the wire version and a handshake KAT re-record; lands at a testnet alpha cut. |
| NI-Q6 | The pool seal. | OPEN (PR 4): records the network id; the chain store needs no field. |
| NI-Q7 | The marker file. | OPEN (PR 4): daemon-config's call (DC-Q15, IG-Q17); recommendation: a label, trusted for nothing. |
| NI-Q8 | Regtest as an ordinary network. | BUILDING (PR 1): §2.5; corpus re-captured through #1244's path. The address byte is persisted in wallet files and multisig addresses (NI-F5), so the wallet-file codec takes rule 42's version bump; an older file is refused with a reason, never reinterpreted. |
| NI-Q9 | The domain-registry audit. | OPEN (PR 2): an audit table over `CRYPTO_DOMAIN_REGISTRY.tsv`; each row bound to the network id or shown unable to replay. NI-F2's two bindings, message signing's enum code and key derivation's name label, move to the genesis-derived network id, with a KAT re-record. |
| NI-Q10 | Compatibility at the handshake, replacing genesis rotation. | SHAPE RULED 2026-11-03 (§3); OPEN (PR 3): what the rules digest covers per step, and the frozen-tuple gate shrinks or goes. |
| NI-Q11 | Regtest's levers. | RULED 2026-11-03 (NI-R6, NI-R8); BUILDING (PR 1). |
| NI-Q12 | Seed format. | RULED 2026-11-03 (NI-R7, NI-R10); BUILDING (PR 1): BIP39, 24 words, on every network; one derivation from the 32 entropy bytes (NI-F8), salted by the network's name. |

## 6. Census at this ground: where the code branches on the network

Read from the tree at `8f2b68dbbf`, non-test code. **Data** is a value selection that becomes a lookup in the network's row; **alias** treats regtest as mainnet; **divergence** is a different code path. PR 1 turns every data site into a row lookup and deletes every alias and every divergence; regtest's levers become the row's `permits` (NI-R6).

| Site | Branch | Class | PR 1 |
| --- | --- | --- | --- |
| `shekyl-daemon-config/src/network.rs` `address_network`, `p2p_port`, `rpc_port` | regtest → mainnet's prefixes and ports | alias | the row; regtest's own |
| `shekyl-daemon-config/src/sections/mod.rs`, `shekyl-node/src/lib.rs` | the mining address decoded as mainnet's on regtest | alias | the row |
| `shekyl-node/src/genesis.rs` `pin_network`, `daemon_network` | which genesis to connect; regtest reported as `Fakechain` | alias | the table |
| `shekyl-node/src/lib.rs` `genesis_pin_of` | the store pinned to mainnet's genesis on regtest | alias | the table |
| `shekyl-node/src/lib.rs` `sync_at_open` | regtest opens `Synced`, the others `NoView` | divergence | one rule for every network |
| `shekyl-node/src/lib.rs` `rules_of`; `shekyl-chain-ingest/src/schedule.rs` `Chain`, `ChainRules`, `in_force` | regtest takes `RuleSet::fakechain`, the others `RuleSchedule::for_network` | divergence | the rule schedule is a row field; fixed difficulty is data in it |
| `schedule.rs` `trust`; `shekyl-chain-rules/src/rules/genesis.rs` (CEN-E1) | regtest validates `Trust::UNPINNED`, so its block 0 is never checked | divergence | every network pinned from the table |
| `schedule.rs` `ChainRules::new`; `shekyl-chain-ingest/src/connector.rs`; `corpus.rs` `check_inject`; `shekyl-chain-store/src/store/archival_write.rs` | levers (inject serve credit, issue draws) refused off regtest; the store keys "is regtest" on an unpinned trust | divergence | the row's `permits` (NI-R6) |
| `shekyl-rpc-types/src/identity.rs` `genesis_hash_for`, `exact_or_fakechain`, `check_tuple`; `shekyl-engine-core/src/engine/daemon/mod.rs` `FakechainPolicy` | a fakechain daemon passes a mainnet wallet's identity check | alias | deleted; exact match only |
| `shekyl-ffi/src/network_id_ffi.rs` | regtest's network id is mainnet's | alias | the table |
| `shekyl-daemon-rpc/src/console/info.rs` `network_label` | regtest shown as "mainnet" | alias | the row's name |
| `shekyl-crypto-pq/src/account.rs` `to_address_network` | regtest → mainnet's prefixes | alias | the row |
| `shekyl-crypto-pq/src/account.rs` `permitted_seed_format`; `shekyl-wallet-rpc/src/lifecycle.rs`; `shekyl-genesis-tool/src/wallets.rs` | BIP39 on mainnet and stagenet, Raw32 on testnet and regtest, by separate code paths | divergence | BIP39, 24 words, everywhere (NI-R7) |
| `shekyl-ffi/src/dialer_ffi.rs` `note_network`; `shekyl-dialer/src/seeds.rs` | stagenet and regtest get no seeds; a second copy of the ports | data | the row's seed list, empty where there are none |
| `shekyl-cli/src/commands/mine.rs` | regtest refused | divergence | all four rows |
| `shekyl-engine-state/src/safety_constants.rs` `for_network` | per-network wallet constants; no regtest row | data | a row field |
| `shekyl-engine-core/src/engine/lifecycle/support.rs`, `shekyl-wallet-rpc/src/lifecycle.rs`, `shekyl-genesis-tool/src/wallets.rs` | three copies of address network → derivation network | data | deleted: one type |
| `src/cryptonote_config.h` `get_config` | `case FAKECHAIN: return mainnet;`, the live C++ handshake id and ports | alias | regtest's own config, its id from the table |
| `src/cryptonote_basic/cryptonote_basic_impl.cpp` `nettype_to_ffi_network`; `src/cryptonote_basic/account.cpp` | FAKECHAIN → mainnet's address byte | alias | regtest's byte |
| `src/common/util.cpp` `cumulative_block_sync_weight` | `nettype != MAINNET` returns a block count | divergence | one rule |

Guards that compare a configured network with a recorded one (the marker, the miner address, the wallet file's network byte, the recipients file) are equality checks, not branches, and stay.

## 7. Findings

- **NI-F1 — at `8f2b68dbbf`: the Noise prologue already binds the network id.** `Initiator` and `Responder` build their symmetric state with `Sym::new(PROTOCOL_NAME, network_id)` (`shekyl-p2p-transport/src/noise.rs`), since `6fd0c524da` (2026-09-24); `wrong_prologue_and_wrong_suite_fail_like_garbage` holds it. A handshake with another network's node already fails at message two. NI-Q5 is therefore the wire version only.
- **NI-F2 — at `8f2b68dbbf`: message signing and wallet derivation separate networks by enum code and name label, not by the derived id.** The message-signing preimage binds `DerivationNetwork::as_u8` (`shekyl-crypto-pq/src/message_signing.rs`), and the derivation salt carries a per-network label (`salt_label`, `shekyl-crypto-pq/src/account.rs`). Both separate the four networks today, but by a code that exists apart from the genesis. NI-Q9 decides whether each binds the derived id; under NI-R5 the id never changes, so either is stable.
- **NI-F3 — at `8f2b68dbbf`: one regtest node reads its own network three ways.** The store opens with `GenesisPin::FAKECHAIN`, mainnet's genesis (`shekyl-node/src/lib.rs` `genesis_pin_of`); `validate` receives `Trust::UNPINNED` and skips CEN-E1 (`shekyl-chain-ingest/src/schedule.rs` `trust`); and the store's regtest-only writes require `genesis_pin() == NONE` (`shekyl-chain-store/src/store/archival_write.rs`), which holds only because ingest hands them its own trust rather than the store's pin. "Unpinned" stands in for "is regtest". With regtest a row, every network is pinned, and a lever's permission is a row field (NI-Q11).
- **NI-F4 — at `8f2b68dbbf`: no C++ in `src/` reads `GENESIS_TX` or `GENESIS_NONCE`.** Their readers are Rust parsing the header as text (`shekyl-node/src/genesis.rs`, `shekyl-genesis-tool/src/config_pin.rs`) and C++ tests under `tests/`. NI-Q3 deletes them outright, with no FFI read. C++ still takes the network id and ports for its handshake from `get_config`, whose id already comes from Rust (`shekyl_network_id`).
- **NI-F5 — at `8f2b68dbbf`: six numeric encodings of the network.** The cryptonote code, `DaemonNetwork`, `DerivationNetwork::as_u8` and the `CorpusNet` tag (0–3), and `shekyl_address::Network::as_u8` (0–2), which is persisted as the wallet file's network byte (`shekyl-engine-file/src/handle.rs`) and inside multisig addresses (`shekyl-address/src/multisig_address.rs`). The one network type has one code. Regtest gives the address byte a fourth value, so the wallet-file codec takes rule 42's version bump in PR 1.
- **NI-F6 — at `8f2b68dbbf`: the inject lever is live, as a corpus replay event.** A corpus `inject` record is `IngestEvent::Inject` (`shekyl-chain-ingest/src/corpus.rs`); the pipeline hands it to the connector's `Inject`, which writes through `ChainStore::regtest_inject_serve_credit` (`shekyl-chain-store/src/store/archival_write.rs`). Issue draws (`ChainStore::regtest_issue_draws`) take the same door. No RPC lever reaches either, but the archival corpus chains replay through them, so both are `permits` entries on regtest's row, not stale names.
- **NI-F7 — at `8f2b68dbbf`: the existing armed-lever gate admits three levers on testnet and stagenet.** The gate is per option: each `dev-*` row in `shekyl-daemon-config/src/table.rs` lists the networks that accept it (`Visibility::Dev { networks }`), and `dev-rpc` is the switch `admit_armed` reads for `generateblocks` and `pop_blocks`. `dev-rpc`, `dev-relay-cover` and `dev-clearnet-encrypt` are listed for testnet, stagenet and regtest; every other `dev-*` row is regtest's alone. NI-R6's invariant (`permits` empty on every row but regtest's) removes those three from testnet and stagenet. RULED 2026-11-03: `dev-rpc` becomes regtest's (NI-R8); the other two are staging flags (NI-R9).
- **NI-F8 — at `8f2b68dbbf`: the seed format is a derivation input, and NI-R7 removes it.** 24 words is already the only length (`SHEKYL_MNEMONIC_WORD_COUNT`, `shekyl-crypto-pq/src/bip39.rs`); a BIP39 passphrase is accepted, opt-in; and a BIP39 wallet derives from the PBKDF2 output (`mnemonic_to_pbkdf2_seed`). `SeedFormat` (`Bip39` / `Raw32`, `shekyl-crypto-pq/src/account.rs`) is bound into the derivation salt (`salt_label`) and the wallet-file AAD. Once derivation takes the 32 entropy bytes on every network, a phrase and a harness's fixed key are the same input, so the format leaves the salt and the AAD: one derivation per network, and the words are how the 32 bytes are shown. PR 1 re-records the derivation KATs (mainnet's included), deletes the passphrase and the PBKDF2 path, and folds the AAD change into the same wallet-file version bump as NI-F5.
- **NI-F9 — at `8f2b68dbbf`: key derivation can't bind the genesis-derived network id.** RULED: NI-R10. The genesis pays its recipients' addresses, the addresses come out of key derivation, and the network id is a hash of the genesis. Derivation bound to that id would need the genesis before the genesis exists. Derivation binds the network's name, the row's tag `shekyl/<network>` (NI-R10).
- **NI-F10 — at `8f2b68dbbf`: the public networks' genesis recipients are derived addresses, and NI-R7 moves them.** RULED: NI-R11. `config/genesis_recipients.{mainnet,testnet,stagenet}.json` hold addresses the custodians derived from their seeds (`geblock wallets`, `shekyl-genesis-tool/src/wallets.rs`) under today's derivation. NI-R7 changes the derivation (the format leaves the salt; the words give the 32 entropy bytes, not PBKDF2's output), so the same seeds give different addresses, and a genesis rebuilt from today's files would pay addresses no wallet can spend. Every change to key derivation, including NI-R10's name, therefore lands in PR 1, before the one regeneration, or PR 2 forces a second regenesis.

## 8. Shape and order

1. **PR 1 — the table (NI-Q1, Q2, Q3, Q8, Q11, Q12).** The crate and the one network type; all four networks' genesis rebuilt once by the tool; regtest's prefixes and its `permits`; the staging class (NI-R9); `dev-rpc` regtest-only (NI-R8); the fakechain deletions; the wallet-file version bump; BIP39, 24 words, and the single derivation, salted by the network's name (NI-R10), on every network; the test networks' recipients regenerated and mainnet's row PROVISIONAL (NI-R11); pins and KATs regenerated; corpora re-captured; the C++ genesis constants deleted; the frozen-tuple gate repointed at the table so it stays readable until PR 3. Lands first; everything else reads the table.
2. **PR 2 — the signing domain and the audit (NI-Q4, Q9).** One consensus PR.
3. **PR 3 — the handshake (NI-Q10, Q5).** The rules check in message one and the wire version in the prologue; one wire PR, at a cut; the frozen-tuple gate shrinks or goes in the same PR.
4. **PR 4 — the pool seal and the marker (NI-Q6, Q7).**
5. **The S3 round (DRS, [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §11.1).** The operator store tools, including "rewind N blocks", which replaces `pop_blocks` (NI-R8).

## 9. What it closes, and what it costs

**Closes:** the mainnet-store-opened-as-regtest hole; the regtest node handshaking with mainnet (FOLLOWUPS "Fakechain derives mainnet's handshake id"); cross-network transaction replay, by construction; the marker as an authority; the C++ genesis constants; FOLLOWUPS row 7 (RD-Q7); every fakechain special case; genesis rotation as a release mechanism.

**Costs:** one regenesis of every network, in PR 1 (mainnet's genesis isn't final; testnet and stagenet restart once); a signing-preimage change with a KAT re-record, wallet and daemon in one PR, which is a pre-genesis-only change; a handshake change that every node of a network takes at one cut; one new crate, and the deletion of four network enums and the C++ genesis constants.
