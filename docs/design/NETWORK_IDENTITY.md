# Network identity — one pathway for every network: Round 0 (`NI-`)

**Families (registered in `IMPLEMENTATION_INDEX.md` §2, rule 94):** **`NI-R`** (rulings), **`NI-Q`** (questions) and **`NI-F`** (findings). `NI-` is free at `8f2b68dbbf`.
**Ground:** `feat/drs-s1-no-checkpoints` at `8f2b68dbbf` (#1263, 2026-11-03), read from the tree. The design review's first draft read `dev` at `b8f1b76c0`; the two places this ground differs from that draft are NI-F1 and NI-F2.
**Status:** OPEN — Round 0. NI-R1…NI-R12 RULED by Rick 2026-11-03, NI-R13…R15 on 2026-11-04 (NI-R6 rules NI-Q11, NI-R7 NI-Q12, NI-R8 and NI-R9 NI-F7, NI-R10 NI-F9, NI-R11 NI-F10, NI-R12 amends NI-R10, NI-R13 places NI-Q4's id, NI-R14 rules NI-F11, NI-R15 NI-F13); NI-Q10's shape RULED the same day (§3). PR 1 (NI-Q1, Q2, Q3, Q8, Q11, Q12) is built on #1264, every census row of §6 disposed (two carried by #1237); PR 2 (NI-Q4, Q9 and NI-F2) is built on #1266; NI-Q5…Q7 and Q10 follow in §8's order. Mainnet's row is PROVISIONAL until the genesis ceremony (NI-R11). Each row of §5 carries its own status.
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
- **its name in the genesis transaction key** (NI-R12): the key is derived from a message that starts with the row's name and carries every recipient's keys and amount (`shekyl-genesis-tool/src/txkey.rs`). Two networks can't collide even with identical recipients, and a tool identifies a genesis by matching its hash against the table, or by recomputing the key from each known name. There is no coinbase field: the coinbase grammar (CEN-I20) is the same at every height.

Regtest then shares **no state** with mainnet: no output, no curve-tree leaf, no root.

### 2.3 One genesis table, in Rust (NI-Q3)

One crate holds one table: `network → { name, genesis block bytes, genesis hash, address prefixes, rule set, seeds, ports, difficulty parameters }`, and one network type. Everything reads it:

- `genesis_hash_for`, `GenesisPin`, `network_id_from_genesis`, the wire prefix, the marker, the RPC identity, the address codec, wallet derivation, seeds;
- the remaining C++ through the FFI it already uses for the network id (`shekyl_network_id`), never a copy of its own. `cryptonote_config.h`'s `GENESIS_TX` / `GENESIS_NONCE` are deleted: no C++ in `src/` reads them (NI-F4).

**Tests that hold it, over all four networks:** (a) each network's genesis block, rebuilt from its definition by the genesis tool, hashes to the pinned hash; (b) every network's genesis hash, network id, wire prefix and address-prefix set are pairwise distinct; (c) each genesis's transaction key recomputes from its row's name and recipients file.

### 2.4 Bind the identity wherever cross-network confusion could matter

- **Transaction signing (NI-Q4, NI-F12).** Every proof and signature over a transaction commits to the network through one network-bound message, `tx_signable` (§2.4.1). A signature or proof is then valid on exactly one network by construction, not because tree roots happen to differ.
- **Noise prologue (NI-Q5).** The prologue is `network id ‖ wire-protocol version`. The network id is already there (NI-F1); the wire version joins it.
- **Pool file (NI-Q6).** Its seal records the network id. The chain store needs no field: it has block 0.
- **Marker file (NI-Q7).** A derived label for humans and tooling; nothing trusts it for identity, because every holder of chain data checks the genesis-derived id itself.
- **Every other domain (NI-Q9).** Audit [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv): every signature or commitment that could be replayed across networks binds the network id, or is shown unable to replay.

### 2.4.1 PR 2's shape: one signing envelope (NI-Q4, NI-Q9, NI-F2, NI-F11…F13; #1266)

Ruled in full by Rick on 2026-11-04 (the signing envelope, `claude/NI_SIGNING_ENVELOPE.md` in `shekyl-dev`; NI-R13…R15 and the rulings of 23:42). Every Shekyl-owned hash, signature and proof that binds the network derives its message through one function, `shekyl_network::envelope`:

```text
framed(b)                      = u64_le(len(b)) ‖ b
frame(domain, binding, fields) = cSHAKE256(S = domain, X = binding ‖ framed(f_1) ‖ … ‖ framed(f_n))
```

- **The domain** is a registered constant (`CRYPTO_DOMAIN_REGISTRY.tsv`), versioned in its own name; a layout change is a new domain, and no version byte is hashed beside it.
- **The binding** is 16 bytes at position 0: the genesis-derived network id for anything signed or proved against the chain (an `IdDomain`), or `name_id = cSHAKE256(S = "shekyl/network-name-v1", X = "shekyl/<network>")[..16]` for anything derived from keys or addresses, which exist before genesis (a `NameDomain`; NI-R10, NI-R15). The domain constant's type carries its binding, its field count and its width, so a call site that passes the other binding, another number of fields or reads another width does not compile.
- **The width** is 64 bytes for content a post-quantum or hybrid signature signs, because a 32-byte digest caps collision resistance at 2^128, below ML-DSA-65's and SLH-DSA-192s's Category 3; 32 otherwise (16 for the two bindings).

**One transaction message (NI-F12, ruled (b)).**

```text
tx_signable    = frame("shekyl/tx-signable-v1", id, [prefix_hash, ct_base_hash])
signed_hash(i) = frame64("shekyl/fcmp-spend-signing-v2", id,
                         [tx_signable, header(i), key_hashes, prunable_hash])
```

- `prefix_hash` is CEN-J22's signable prefix hash (the prefix hash with the emission input removed whole; the plain prefix hash when there is none), and `ct_base_hash` is the txid's base component, `H(base)`; both come from the functions `shekyl-wire` uses for the txid.
- The FCMP++ SAL (full and membership-only) and FROST prove over `tx_signable`, so every proof over a transaction commits to the network itself. An emission's backing proof proves over the same message, and both emission auths are `frame64` under `shekyl/archival-emission-auth-{backing,claim}-v4`, field 8 `tx_signable` and field 9 the backing's wire bytes (NI-R14). Every byte of the emission input is then a field both auths sign or one of their signatures, which are verified strictly: canonical encodings only, and Ed25519's strict verify (a small-order key or R refused) beside ML-DSA's.
- Each input's hybrid signature signs `signed_hash(i)` (`SigningPayloadHash`, 64 bytes); the validator takes the id from the genesis its `Trust` pins, and a harness chain under `Trust::UNPINNED` signs and verifies under `HARNESS_NETWORK_ID` (test and harness builds only).
- The KAT keeps the eight C++-captured payloads; its oracle takes them apart itself and pins `tx_signable` and each `signed_hash` per network ([`FCMP_SPEND_SIGNING_PREIMAGE.md`](FCMP_SPEND_SIGNING_PREIMAGE.md)).

**Message signing (NI-F2).** `preimage = frame64("shekyl/msg-sign-v2", id, [u64_le(mode), classical_segment, message])`: the id at position 0, the message framed whole (its pre-hash domain is retired), and the decoded wire format's layout version, 2, read and not hashed ([`WALLET_MESSAGE_SIGNING.md`](WALLET_MESSAGE_SIGNING.md) SM-R-3; `docs/test_vectors/MSG_SIGN_PREIMAGE_V2.json`).

**Proofs (NI-F13, NI-R15).** A tx proof's Schnorr signs `frame("shekyl/tx-proof-{outbound,inbound}-v1", id, [txid, address_bytes, user_message, per_output_data])`, a reserve proof's `frame("shekyl/reserve-proof-message-v1", id, [address_bytes, user_message, per_output_data])`, and each DLEQ binds `frame("shekyl/reserve-proof-dleq-context-v1", id, [address_bytes, user_message, output_key])`. The canonical address bytes are the address alone (spend ‖ view ‖ ML-KEM key), and both proof versions are 3.

**Multisig fingerprint (NI-R15).** `frame("shekyl/multisig-address-v3", name_id, [canonical payload])` (`docs/test_vectors/MULTISIG_FINGERPRINT_V3.json`).

**Key derivation (NI-R16).** The HKDF salt is `name_id ‖ purpose` (`salt_for`), from PR 1.

**Wire size.** Unchanged everywhere: every binding is hashed, never carried.

**The registry's bindings and the gate (NI-Q9; ruled 2026-11-04 and 2026-11-05).** Every production row of [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) carries a `binding`, a `width` and a `role`:

- **Binding,** one of six, each from a closed list: `id`; `name`; `input:<type>` (its input holds a value already network-bound: `TxSignableHash`, `SigningPayloadHash`, a `frame` output (`Framed32` or `Framed64`, by width), `BlockHash`, `TxId`, the FCMP++ tree root or anchor, a key derived under `salt_for`, an RPC daemon's `StaticPublic` bundle, or the `Mac1Tag` made under its key; `BlockHeader` is refused); `derived:<CEN rule>` (every verifier recomputes it from its own chain under the named census rule); `local:<why>` (`wallet-file-key`, `p-store-key`, `store-codec`, `per-output-secret`, `display-only`, `host-tor-client`, `key-intermediate`, `verifier-randomness`, `checksum`); `enclosed-by:<row>` (third-party internals, fixed public parameters and the six SAL hedged nonces only). `shekyl/network-name-v1` and `shekyl/p2p-network-id-v1` are the two binding derivations.
- **Width,** the bytes the row's consumers read; **role,** `signed` (a post-quantum or hybrid signature's content), `auth` (its verification is evidence of authorship or authenticity) or `plain`.

The gate (`rust/shekyl-crypto-pq/tests/domain_binding.rs`) parses the code with `syn` and refuses: a value off the closed lists; a cSHAKE `id` or `name` row that is not an `IdDomain` or `NameDomain` constant of that kind and width, or such a constant whose row says otherwise; an HKDF `name` row defined away from `salt_for`; a Noise handshake whose prologue is not built from a `&NetworkId`; an `input:<type>` row unless every production function that applies its domain constant carries the type, through a parameter, a typed binding, a field of one of those types, a same-file function it calls, or another method of the same type (a slice, a `Vec`, an array or a tuple of the type carries it); `local` on a `signed` or `auth` row; `derived:` naming no census row; `enclosed-by` on a Shekyl-owned row; `signed` content narrower than 64 bytes; and any Rust source holding a label from the registry's retired-after-genesis section, which is empty before genesis. Each check has a control that feeds it a bad row or source and asserts the refusal.

Rows the code cannot meet yet are listed in [`DOMAIN_BINDING_RATCHET.tsv`](DOMAIN_BINDING_RATCHET.tsv), which only shrinks (its counts are pinned in the gate, and a listed row the gate can already prove is refused until removed) and must be empty at v3.1.0 (`scripts/release/check_binding_ratchet.py`, run at the cut and on every pull request): 7 `input:` rows: 2 whose site takes raw bytes (owner: SO-D12 4b) and 5 whose input is not yet a key derived under `salt_for` by type, each waiting on a ruling its note names (owner: SO-D12), 2 `id`/`name` rows not declared as domain constants, and 7 rows with no ruled binding.

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
- **NI-R4 — RULED 2026-11-03: one pathway for every network, no exemptions.** All four networks get a tool-built genesis with nonce 0, its name bound through the transaction key (NI-R12). Testnet and stagenet regenesis once, in this round. Both nonce fields stay: the header nonce for proof of work and the coinbase-extra nonce for pooled mining. Genesis writes zero in both, and neither identifies a network.
- **NI-R5 — RULED 2026-11-03: no genesis rotation, ever.** Compatibility is NI-Q10's handshake check, not a regenesis.
- **NI-R6 — RULED 2026-11-03 (NI-Q11): regtest's levers are a `permits` field on the network's row.** One gate reads it, the existing armed-lever gate, answering from the row; the scattered "is regtest" and "is the trust unpinned" checks go (NI-F3). The field is compiled into the table, never configurable. Invariant test: `permits` is empty on every row but regtest's. Its entries include the inject-serve-credit and issue-draws writes, which the archival corpus chains replay through (NI-F6), and `dev-rpc` (NI-R8).
- **NI-R7 — RULED 2026-11-03 (NI-Q12): one seed format on every network: BIP39, 24 words only.** No 12-word option, not even on import: 128 bits is 64 bits of quantum security under Grover, below Shekyl's post-quantum floor. No BIP39 passphrase: its PBKDF2 stretch is weak, and the wallet file has its own encryption. Derivation takes the 32 entropy bytes the words encode, not BIP39's PBKDF2 output. **One secret, one derivation (NI-F8):** words and raw hex are two spellings of the same 32 bytes and yield the same wallet, so the seed format leaves the derivation salt and the wallet file's authenticated data. The network stays in the derivation, as the network's name (NI-R10), so the same 32 bytes on two networks give unrelated keys. Every key-derivation vector is re-recorded, mainnet's included; the wallet-file change rides regtest's address-byte version bump (NI-F5). Raw32 survives only as harness input where a fixture injects a fixed key, the genesis tool's recipient wallets included.
- **NI-R8 — RULED 2026-11-03 (NI-F7): `dev-rpc` is regtest-only.** `generateblocks` on a real-difficulty network is `start_mining`; it is a shortcut only where difficulty is fixed. `pop_blocks` leaves the RPC entirely and becomes "rewind N blocks" in the S3 operator store tools, on every network including mainnet, beside "move aside and rebuild". Until that tool lands, `pop_blocks` is a regtest `dev-rpc` lever like `generateblocks`; it leaves the RPC in the change that ships its replacement.
- **NI-R9 — RULED 2026-11-03 (NI-F7): staging is a named class, separate from `permits`.** A staging flag stages a candidate mainnet behaviour on the test networks; it is not a test-only shortcut. Every staging flag names its owner and its exit (promoted to default behaviour, or deleted); it is accepted on the test networks only. **Amended 2026-11-04 (Rick, design review brief §1.1):** staging may continue after mainnet genesis, so the genesis-cut test is withdrawn; instead every flag names a **deadline release** (`Staging::deadline`), and the release gate (`scripts/release/check_staging_deadlines.py`, `RELEASE_PROMOTION.md` §4) refuses a cut at or past it while the flag still exists, unless the deadline is re-ruled with a recorded reason. Mainnet never stages (`staging_is_the_test_networks_and_never_mainnets`). Members at this ground: `dev-clearnet-encrypt` (owner: the Noise flip; exit: deleted at the flip) and `dev-relay-cover` (owner: the cover-traffic lane, TRC-1; exit: its outcome), each with the genesis release `v3.1.0` as its deadline: mainnet launches with both behaviours in final form (`RELEASE_CHECKLIST.md`). The class gives a future rollout a sanctioned route without bending the one-pathway rule.
- **NI-R10 — RULED 2026-11-03 (NI-F9): the network has two forms, a name and an id.** The **name** is the root: the static tag `shekyl/<network>`, compiled into the table, used wherever genesis can't exist yet: key derivation, address prefixes, and the genesis transaction key, derived from it (NI-R12). The **id** is derived, `cSHAKE256(NETWORK_ID_DST, genesis hash)[..16]`, used everywhere after genesis exists: the handshake and wire prefix, the store pin, the pool seal, and transaction and message signing (NI-Q4, NI-Q9). The two are bound one-to-one: genesis commits to the name through its transaction key, so the id commits to the name. Invariant tests over all four rows: the transaction key recomputes from the row's name and recipients file, the genesis rebuilds to the pinned hash, and names are pairwise distinct.
- **NI-R11 — RULED 2026-11-03 (NI-F10): the test networks' recipients are regenerated in PR 1; mainnet's at the genesis ceremony.** Testnet, stagenet and regtest use test recipients and test keys, regenerated in PR 1 under the new derivation, pins included. Mainnet's custodians keep their seeds; only the addresses derived from them move, because the salt changed. They re-derive with the new tool and deliver new recipients files, each confirming their own address: a ceremony with real people and real seeds, not on a PR's clock. Mainnet's row lands in PR 1 marked PROVISIONAL, with the tool path ready, and is pinned the same way as the test networks once the files are back; mainnet's genesis isn't final, so nothing ships on a provisional pin. A custodian holding a raw 32-byte seed is shown the 24 words for the same bytes; under NI-R7 that is the same secret, so no key changes.
- **NI-R12 — RULED 2026-11-03 (amends NI-R10): the name enters genesis through the transaction key, not a coinbase field.** The genesis transaction key is derived from a message that starts with the network's name and includes every recipient's keys and amount, so every genesis already commits to its name; genesis is transparent and rebuildable from its recipients file, which is why a public transaction key is sound there. A genesis-only coinbase field would write a height-0 exception into the consensus grammar (CEN-I20), which NI-R4 rules out; a field in every coinbase would pay bytes forever to repeat what genesis fixes. Readability needs no field: match the hash against the table, or recompute the key from each name. The txkey message's name is the table row's name constant, never a literal, and regtest joins the set.
- **NI-R13 — RULED 2026-11-04 (NI-Q4's placement): the network id goes in the hash input, not the customization string.** Both are sound, since cSHAKE length-encodes S; the input keeps the domain registry a list of constant strings, so the audit is over strings, not patterns, and a fixed 16 bytes at a fixed position is unambiguous without framing. Every network-bound hash states its id's position and width, ahead of any variable-length field (spend signing: byte 0 of `X`; message signing: byte 1, after the layout version; emission auths: byte 0). This corrects NI-Q4's row, which said the customization.
- **NI-R14 — RULED 2026-11-04 (NI-F11): the emission auth message starts with the network id.** The audit's standard is "bound, or shown unable to replay"; an emission may have no fee input to lean on, so it binds explicitly: 16 bytes at byte 0, with a known-answer test that fails if they are removed.
- **NI-R15 — RULED 2026-11-04 (NI-F13), following NI-R10's name/id split: derived from keys or addresses ⇒ the name; signed or proved against the chain ⇒ the id.** Reserve proofs and their DLEQ are made against a chain after genesis and take the id (so do the tx proofs, which share their address bytes). The multisig fingerprint is derived from keys and addresses, which exist before any genesis, and takes the name.
- **NI-R16 — RULED 2026-11-04 (amends NI-R10's key derivation; Rick's ruling 2 on the signing envelope): the derivation salt is the name's 16-byte binding, then the purpose.** `salt = name_id ‖ "shekyl-master-derive-v3"`, with `name_id = cSHAKE256(S = "shekyl/network-name-v1", X = "shekyl/<network>")[..16]`, held on each table row and pinned for all four networks; it replaces `shekyl-master-derive-v2-` ‖ tag. It lands in PR 1, so testnet, stagenet and regtest are regenerated once: their recipients, genesis blocks, network ids, the captured chains and the vector suites move here and not again in PR 2. The rest of the signing envelope is PR 2's.
- **NI-R17 — RULED 2026-11-04 (NI-F12 (b) in the universal form; the signing envelope, with the rulings of 23:42): one framing function, one transaction message.** Every Shekyl-owned hash, signature and proof that binds the network derives its message through `frame` (§2.4.1), its binding the id or `name_id` at position 0 and its width 64 where a post-quantum or hybrid signature signs it; every authorization of a transaction proves over `tx_signable`, which is framed over CEN-J22's prefix hash (so emissions have no separate message); proofs bind by frame, with plain address bytes; the registry carries one of five bindings per row (`id`, `name`, `input:<type>`, `local:<why>`, `enclosed-by:<row>`, closed lists) and a width, and a CI gate keeps them true. Supersedes NI-R13's per-site positions: the id is at position 0 of every frame.

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
| NI-Q2 | What the genesis content carries. | BUILDING (PR 1): recipients and a transaction key derived from the row's name (NI-R12), the same shape on every network; no coinbase field; regtest's recipient and key committed and marked test-only (§2.2). |
| NI-Q3 | The one Rust table: fields, readers, the network type; the C++ genesis constants. | BUILDING (PR 1): §2.3; the C++ genesis constants deleted outright (NI-F4); one network type with one code (NI-F5); tests (a)–(c) over all four networks. |
| NI-Q4 | The signing domain. | BUILT (PR 2, #1266, §2.4.1): every SAL and FROST proof and each input's hybrid signature are over the transaction's one network-bound message, `tx_signable`; the spend hash is `frame64(shekyl/fcmp-spend-signing-v2, id, [tx_signable, header(i), key_hashes, prunable_hash])`; signer, verifier (CEN-I15, I17, I18, the id from `Trust`) and KAT in one PR; `FCMP_SPEND_SIGNING_PREIMAGE.md`. |
| NI-Q5 | The Noise prologue. | OPEN (PR 3): `network id ‖ wire-protocol version`; the network id is already the prologue (NI-F1), so the change is the wire version and a handshake KAT re-record; lands at a testnet alpha cut. |
| NI-Q6 | The pool seal. | OPEN (PR 4): records the network id; the chain store needs no field. |
| NI-Q7 | The marker file. | OPEN (PR 4): daemon-config's call (DC-Q15, IG-Q17); recommendation: a label, trusted for nothing. |
| NI-Q8 | Regtest as an ordinary network. | BUILDING (PR 1): §2.5; corpus re-captured through #1244's path. The address byte is persisted in wallet files and multisig addresses (NI-F5), so the wallet-file codec takes rule 42's version bump; an older file is refused with a reason, never reinterpreted. |
| NI-Q9 | The domain-registry audit. | BUILT (PR 2, #1266): Appendix A classed 131 rows at its ground; NI-F11…F13 RULED and built (NI-R14, NI-R15, NI-R17). The registry's `binding`, `width` and `role` columns carry the classification, held by the binding gate and its ratchet (§2.4.1). NI-F2: message signing binds the id at position 0 of its frame. |
| NI-Q10 | Compatibility at the handshake, replacing genesis rotation. | SHAPE RULED 2026-11-03 (§3); OPEN (PR 3): what the rules digest covers per step, and the frozen-tuple gate shrinks or goes. |
| NI-Q11 | Regtest's levers. | RULED 2026-11-03 (NI-R6, NI-R8); BUILDING (PR 1). |
| NI-Q12 | Seed format. | RULED 2026-11-03 (NI-R7, NI-R10); BUILDING (PR 1): BIP39, 24 words, on every network; one derivation from the 32 entropy bytes (NI-F8), salted by the network's name. |

## 6. Census at this ground: where the code branches on the network

Read from the tree at `8f2b68dbbf`, non-test code. **Data** is a value selection that becomes a lookup in the network's row; **alias** treats regtest as mainnet; **divergence** is a different code path. PR 1 turns every data site into a row lookup and deletes every alias and every divergence; regtest's levers become the row's `permits` (NI-R6). Two divergences sit in code chain sync's cutover replaces, so #1237 (CS-5) carries them and PR 1 does not edit code about to go; the Disposition column says which.

| Site | Branch | Class | PR 1 | Disposition |
| --- | --- | --- | --- | --- |
| `shekyl-daemon-config/src/network.rs` `address_network`, `p2p_port`, `rpc_port` | regtest → mainnet's prefixes and ports | alias | the row; regtest's own | Done: the row (`2c8f53a552`, `ed9c440e06`) |
| `shekyl-daemon-config/src/sections/mod.rs`, `shekyl-node/src/lib.rs` | the mining address decoded as mainnet's on regtest | alias | the row | Done: decoded for the configured network's row |
| `shekyl-node/src/genesis.rs` `pin_network`, `daemon_network` | which genesis to connect; regtest reported as `Fakechain` | alias | the table | Done: the table (`ed9c440e06`) |
| `shekyl-node/src/lib.rs` `genesis_pin_of` | the store pinned to mainnet's genesis on regtest | alias | the table | Done: the table (`ed9c440e06`, `4858d33812`) |
| `shekyl-node/src/lib.rs` `sync_at_open` | regtest opens `Synced`, the others `NoView` | divergence | one rule for every network | #1237 (CS-5): the state at open reads the operator's declaration (offline, closed, open), never the network |
| `shekyl-node/src/lib.rs` `rules_of`; `shekyl-chain-ingest/src/schedule.rs` `Chain`, `ChainRules`, `in_force` | regtest takes `RuleSet::fakechain`, the others `RuleSchedule::for_network` | divergence | the rule schedule is a row field; fixed difficulty is data in it | Done: one `ChainRules` for every network; levers apply onto the network's own set (`4858d33812`) |
| `schedule.rs` `trust`; `shekyl-chain-rules/src/rules/genesis.rs` (CEN-E1) | regtest validates `Trust::UNPINNED`, so its block 0 is never checked | divergence | every network pinned from the table | Done: every network pinned; `Trust::UNPINNED` is test and harness only (`4858d33812`) |
| `schedule.rs` `ChainRules::new`; `shekyl-chain-ingest/src/connector.rs`; `corpus.rs` `check_inject`; `shekyl-chain-store/src/store/archival_write.rs` | levers (inject serve credit, issue draws) refused off regtest; the store keys "is regtest" on an unpinned trust | divergence | the row's `permits` (NI-R6) | Done: `permits`; the store takes a `Permit` (`444f3ac3b3`, `4858d33812`) |
| `shekyl-rpc-types/src/identity.rs` `genesis_hash_for`, `exact_or_fakechain`, `check_tuple`; `shekyl-engine-core/src/engine/daemon/mod.rs` `FakechainPolicy` | a fakechain daemon passes a mainnet wallet's identity check | alias | deleted; exact match only | Done: deleted; exact match (`ed9c440e06`) |
| `shekyl-ffi/src/network_id_ffi.rs` | regtest's network id is mainnet's | alias | the table | Done: the table (`ed9c440e06`) |
| `shekyl-daemon-rpc/src/console/info.rs` `network_label` | regtest shown as "mainnet" | alias | the row's name | Done: the row's name (`08d667da5c`; #1259 moves the console into `shekyl-cli` and carries it there) |
| `shekyl-crypto-pq/src/account.rs` `to_address_network` | regtest → mainnet's prefixes | alias | the row | Done: one derivation, no address-network mapping (`ec931d5858`) |
| `shekyl-crypto-pq/src/account.rs` `permitted_seed_format`; `shekyl-wallet-rpc/src/lifecycle.rs`; `shekyl-genesis-tool/src/wallets.rs` | BIP39 on mainnet and stagenet, Raw32 on testnet and regtest, by separate code paths | divergence | BIP39, 24 words, everywhere (NI-R7) | Done: BIP39, 24 words, everywhere (`ec931d5858`) |
| `shekyl-ffi/src/dialer_ffi.rs` `note_network`; `shekyl-dialer/src/seeds.rs` | stagenet and regtest get no seeds; a second copy of the ports | data | the row's seed list, empty where there are none | Done: the row's seed list (`08d667da5c`) |
| `shekyl-cli/src/commands/mine.rs` | regtest refused | divergence | all four rows | Done: all four rows (`ed9c440e06`) |
| `shekyl-engine-state/src/safety_constants.rs` `for_network` | per-network wallet constants; no regtest row | data | a row field | Done: one set, no field differs by network (`cf587414f7`) |
| `shekyl-engine-core/src/engine/lifecycle/support.rs`, `shekyl-wallet-rpc/src/lifecycle.rs`, `shekyl-genesis-tool/src/wallets.rs` | three copies of address network → derivation network | data | deleted: one type | Done: deleted with `DerivationNetwork` (`ec931d5858`) |
| `src/cryptonote_config.h` `get_config` | `case FAKECHAIN: return mainnet;`, the live C++ handshake id and ports | alias | regtest's own config, its id from the table | Done: deleted; the daemon reads the table (`ed9c440e06`) |
| `src/cryptonote_basic/cryptonote_basic_impl.cpp` `nettype_to_ffi_network`; `src/cryptonote_basic/account.cpp` | FAKECHAIN → mainnet's address byte | alias | regtest's byte | Done: deleted with the C++ account (`ec931d5858`) |
| `src/common/util.cpp` `cumulative_block_sync_weight` | `nettype != MAINNET` returns a block count | divergence | one rule | #1237 (CS-5): its one caller, the C++ sync path, is deleted there, and the function with it |

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
- **NI-F11 — at `5cb6cdba7a`: the emission auth message binds no network on its own.** RULED: NI-R14 (built). It signed `signable_tx_hash`, a prefix hash with no `reference_block`; its binding is the transaction's proofs, and an emission may have no fee input. Its input now starts with the network id. Appendix A §A.8 item 1.
- **NI-F12 — at `5cb6cdba7a`: the SAL and FROST transcripts bind no network on their own.** RULED (b) and built (NI-R17): they prove over `tx_signable`, which carries the id, so no proof over a transaction is bound only by the signature around it (§2.4.1).
- **NI-F13 — at `5cb6cdba7a`: three rows separate networks by `Network::code()`, not by the id or the name.** RULED: NI-R15 (built): the proofs take the id, the multisig fingerprint the name. The multisig address fingerprint, the reserve proof and its DLEQ; a reserve proof carries no txid or height. Appendix A §A.8 item 3.

## 8. Shape and order

1. **PR 1 — the table (NI-Q1, Q2, Q3, Q8, Q11, Q12).** The crate and the one network type; all four networks' genesis rebuilt once by the tool; regtest's prefixes and its `permits`; the staging class (NI-R9); `dev-rpc` regtest-only (NI-R8); the fakechain deletions; the wallet-file version bump; BIP39, 24 words, and the single derivation, salted by the network's name (NI-R10), on every network; the test networks' recipients regenerated and mainnet's row PROVISIONAL (NI-R11); pins and KATs regenerated; corpora re-captured; the C++ genesis constants deleted; the frozen-tuple gate repointed at the table so it stays readable until PR 3. Lands first; everything else reads the table.
2. **PR 2 — the signing domain and the audit (NI-Q4, Q9).** One consensus PR.
3. **PR 3 — the handshake (NI-Q10, Q5).** The rules check in message one and the wire version in the prologue; one wire PR, at a cut; the frozen-tuple gate shrinks or goes in the same PR.
4. **PR 4 — the pool seal and the marker (NI-Q6, Q7).**
5. **The S3 round (DRS, [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §11.1).** The operator store tools, including "rewind N blocks", which replaces `pop_blocks` (NI-R8).

## 9. What it closes, and what it costs

**Closes:** the mainnet-store-opened-as-regtest hole; the regtest node handshaking with mainnet (FOLLOWUPS "Fakechain derives mainnet's handshake id"); cross-network transaction replay, by construction; the marker as an authority; the C++ genesis constants; FOLLOWUPS row 7 (RD-Q7); every fakechain special case; genesis rotation as a release mechanism.

**Costs:** one regenesis of every network, in PR 1 (mainnet's genesis isn't final; testnet and stagenet restart once); a signing-preimage change with a KAT re-record, wallet and daemon in one PR, which is a pre-genesis-only change; a handshake change that every node of a network takes at one cut; one new crate, and the deletion of four network enums and the C++ genesis constants.

## Appendix A. The domain-registry audit (NI-Q9)

**Superseded as the live classification by the registry's `binding` column and its gate (§2.4.1).** What follows is the audit at its ground, kept as the record the column was built from; for any row's binding now, read [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv).

**Ground:** `feat/ni-signing-domain`, with NI-Q4, NI-F2, NI-F11 and NI-F13 built. Every production row of [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) (status `shekyl-live` or `frozen-inherited`, 131 rows) is classed:

- **A, binds the network:** its input carries the network id or name, or something only one chain produces (a genesis-chained header, a block hash, a txid, a tree root, a key derived under the name).
- **B, cannot cross networks:** it is local to one process, file or group, or it is bound to a chain object that a check elsewhere holds to this network.
- **C, replayable:** none.

**Counts:** A = 56, B = 75, C = 0. NI-F11 (four emission rows) and NI-F13 (three rows) are RULED and built (NI-R14, NI-R15). Four B rows, the SAL and FROST transcripts (NI-F12), are B through enclosure, not through their own input; §A.8 brings that back for a ruling.

**The rule for choosing (NI-R15):** anything derived from keys or addresses binds the network's **name** (`shekyl/<network>`), since keys and addresses exist before any genesis (NI-R10); anything signed or proved against the chain binds its genesis-derived **id**. Either sits at a fixed position, ahead of any variable-length field, in the hash input, never in the customization string (NI-R13).

| Mechanism | Rows | A | B |
|---|---|---|---|
| 1 cSHAKE256 | 56 | 32 | 24 |
| 2 HKDF | 44 | 15 | 29 |
| 3 FROST | 4 | 0 | 4 |
| 4 Blake2b | 8 | 0 | 8 |
| 5 Keccak / Schnorr | 14 | 6 | 8 |
| 6 SHA3-256 | 1 | 1 | 0 |
| 7 Noise BLAKE2s | 4 | 2 | 2 |

### A.1 Mechanism 1: cSHAKE256

| Domain | Where | What it hashes | Class | Why |
|---|---|---|---|---|
| shekyl/genesis-txkey-v2 | `rust/shekyl-genesis-tool/src/txkey.rs` | genesis tx secret from the network name and the recipients | A | the preimage starts with `net.name()` |
| shekyl/multisig-address-v2 | `rust/shekyl-address/src/multisig_address.rs` | multisig group fingerprint over the canonical payload | A | the input starts with the network's name, length-prefixed at byte 0 (NI-R15: derived from keys, so the name) |
| shekyl/ek-bind-v1 | `rust/shekyl-address/src/address.rs` | an address's tag over its ML-KEM key | B | lives inside the address; the HRP carries the network and decode checks it |
| shekyl/archival-serve-challenge-leaf-v2 | `rust/shekyl-archival-retention/src/challenge.rs` | challenge leaf index | A | the input includes `prev_block_hash` |
| shekyl/archival-serve-challenge-fire-v1 | `rust/shekyl-archival-retention/src/challenge.rs` | beacon fire height | A | the input includes `block_hash_at_seal` |
| shekyl/pqc-leaf-key-v1 | `rust/shekyl-crypto-pq/src/leaf_commitment.rs` | per-output PQC key scalar k = H(pk) | B | a public pk→scalar map that becomes part of a leaf in that chain's tree |
| shekyl/pqc-leaf-record-v1 | `rust/shekyl-crypto-pq/src/leaf_commitment.rs` | the PQC record over pk and r_h, in tx_extra 0x07 | B | carried inside one tx, so the txid binds it |
| shekyl/archival-serve-credit-response-v1 | `rust/shekyl-archival-retention/src/wire.rs` | the serve-credit signature preimage | A | includes the curve-tree segment subroot and the chain's leaf bytes |
| shekyl/archival-p-id-v1 | `rust/shekyl-archival-retention/src/id.rs` | P_canonical_id over the persona's hybrid pubkey | A | the persona key is derived under `salt_for(net)` |
| shekyl/archival-attestation-root-v1 | `rust/shekyl-archival-retention/src/attestation_wire.rs` | a block's root over its pass records | B | recomputed from the block's own records; the header chains to genesis |
| shekyl/archival-pass-delivery-digest-v1 | `rust/shekyl-archival-retention/src/pass_anchor.rs` | digest of the delivered body, salted by the nonce | B | only signed inside a transcript that carries `anchor_hash` |
| shekyl/archival-shard-view-hash-v1 | `rust/shekyl-archival-retention/src/shard_view_hash.rs` | visualization seed over a shard's txs | A | folds in each txid |
| shekyl/archival-settlement-select-v1 | `rust/shekyl-archival-retention/src/settlement_select.rs` | which issued draws count at settlement | A | the beacon is a block hash |
| shekyl/archival-issued-index-v1 | `rust/shekyl-archival-retention/src/settlement_select.rs` | an issued draw's term in the epoch digest | B | the node's own store-drift check |
| shekyl/archival-draw-v1 | `rust/shekyl-archival-retention/src/secret_draw.rs` | the selection stream | A | input includes `block_hash` |
| shekyl/archival-support-draw-v1 | `rust/shekyl-archival-retention/src/support_draw.rs` | a support draw's shard | A | input includes `block_hash` |
| shekyl/archival-support-challenge-nonce-v1 | `rust/shekyl-archival-retention/src/support_draw.rs` | a support challenge nonce | A | input includes `block_hash` |
| shekyl/archival-draw-commit-v1 | `rust/shekyl-archival-retention/src/secret_draw.rs` | the coinbase 0x0C commitment over witness_pk and seed | B | checked against the 0x0C of block h on the verifier's own chain |
| shekyl/archival-challenge-nonce-v1 | `rust/shekyl-archival-retention/src/secret_draw.rs` | a challenge read's nonce | A | input includes `block_hash` |
| shekyl/archival-serve-credit-batch-v1 | `rust/shekyl-archival-retention/src/secret_draw.rs` | superseded carrier set commitment | B | nothing signs it and no consensus path computes it |
| shekyl/archival-serve-credit-bundle-v1 | `rust/shekyl-archival-retention/src/bundle.rs` | the bundle commitment the witness signs | B | its seed and key are bound to block h's 0x0C |
| shekyl/archival-bundle-prunable-v1 | `rust/shekyl-archival-retention/src/bundle.rs` | content hash of a bundle's prunable bytes | B | a content address carried in a header reference |
| shekyl/archival-bundle-root-v1 | `rust/shekyl-archival-retention/src/bundle.rs` | header root over bundle references | B | recomputed from the references; the header chains to genesis |
| shekyl/archival-drawable-epoch-v2 | `rust/shekyl-archival-retention/src/drawable_epoch.rs` | digest of an epoch snapshot | B | a local store check; no consensus rule reads it |
| shekyl/p-store-aead-v1 | `rust/shekyl-p-store/src/store.rs` | P's body-store file key from file_kek | B | local file |
| shekyl/p-store-slot-v1 | `rust/shekyl-p-store/src/store.rs` | P's per-shard table slot | B | local |
| shekyl/archival-emission-auth-backing-v4 | `rust/shekyl-archival-retention/src/emission_auth.rs` | 64-byte emission auth message (persona, holdings, epochs, work, reward commits, `signable_tx_hash`) | A | the input starts with the network id, byte 0 (NI-R14) |
| shekyl/archival-emission-auth-claim-v4 | `rust/shekyl-archival-retention/src/emission_auth.rs` | the same message under the claim role | A | the same input (NI-R14) |
| shekyl/p-socks-user-v1 | `rust/shekyl-p-transport/src/lib.rs` | Tor SOCKS isolation username from the persona id | B | local to the host's tor client |
| shekyl/output-handle-v1 | `rust/shekyl-crypto-pq/src/handle.rs` | wallet handle for an output position | A | input is view_secret (name-salted) plus tx_hash |
| shekyl/receive-label-hash-v1 | `rust/shekyl-crypto-pq/src/label.rs` | wallet display fingerprint of a label | B | wallet-local display only |
| shekyl/msg-sign-v1 | `rust/shekyl-crypto-pq/src/message_signing.rs` | the message-signing preimage | A | the preimage carries the network id (NI-F2, layout version 2) |
| shekyl/msg-hash-v1 | `rust/shekyl-crypto-pq/src/message_signing.rs` | pre-hash of the message | B | only used inside the msg-sign preimage |
| shekyl/msg-sig-ck-v1 | `rust/shekyl-crypto-pq/src/message_signing.rs` | 4-byte armor checksum | B | not a security check |
| shekyl/pqc-auth-tx-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | hybrid spend auth over `signed_hash` | A | signs `signed_hash`, whose input starts with the network id (NI-Q4) |
| shekyl/pqc-auth-tx-multisig-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | multisig participant auth over the same payload | A | signs the same `signed_hash` |
| shekyl/fcmp-spend-signing-v1 | `rust/shekyl-wire/src/transaction/signing_preimage.rs` | the hash every hybrid spend signature is over | A | X starts with the network id (NI-Q4) |
| shekyl/archival-emission-claim-scheme-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | hybrid signature over the emission claim message | A | signs the claim-role auth message, which starts with the id (NI-R14) |
| shekyl/archival-emission-backing-scheme-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | hybrid signature over the emission backing message | A | signs the backing-role auth message, which starts with the id (NI-R14) |
| shekyl/archival-attestation-scheme-v3 | `rust/shekyl-crypto-pq/src/signature.rs` | pass countersignature transcript | A | the transcript includes `anchor_hash` |
| shekyl/archival-serve-credit-scheme-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | serve-credit response signature | A | message includes the tree subroot |
| shekyl/archival-receipt-scheme-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | serve receipt over the same transcript | A | includes `block_hash(anchor_height)` |
| shekyl/archival-witness-carrier-scheme-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | superseded | B | callers only inside `#[cfg(test)]` |
| shekyl/archival-witness-bundle-scheme-v1 | `rust/shekyl-crypto-pq/src/signature.rs` | witness signature over the bundle commitment | B | the key is fresh per block and committed in h's 0x0C |
| shekyl/snapshot-id-v1 | `rust/shekyl-engine-core/src/engine/refresh/types.rs` | wallet reservation-staleness digest | A | includes block hashes |
| shekyl/chain-digest/v0 | `rust/shekyl-chain-store/src/digest_v0.rs` | outer logical-state digest | A | includes the chain component and the curve root |
| shekyl/chain-digest/v0/chain | `rust/shekyl-chain-store/src/digest_v0.rs` | height-ordered block hashes | A | digest_v0.rs |
| shekyl/chain-digest/v0/spent-elem | `rust/shekyl-chain-store/src/digest_v0.rs` | per-key-image XOR leaf | B | local oracle, nested in the outer digest |
| shekyl/chain-store/undo-log/post-image-v1 | `rust/shekyl-chain-store/src/codec/undo.rs` | post-image of a journaled write | B | local store |
| shekyl/p2p-wire-prefix-v1 | `rust/shekyl-network/src/lib.rs` | clearnet framing prefix | A | X = network_id |
| shekyl/p2p-network-id-v1 | `rust/shekyl-network/src/lib.rs` | the network id | A | X = genesis hash |
| shekyl/rpc-rendezvous-name-v1 | `rust/shekyl-rpc-channel/src/lib.rs` | local rendezvous name | A | input starts with network_id |
| shekyl/rpc-static-fingerprint-v1 | `rust/shekyl-rpc-channel/src/lib.rs` | enrolment id of a client key bundle | B | not a credential; the handshake prologue binds the id |
| shekyl/bp-plus-batch-weights-v1 | `rust/shekyl-bulletproofs/src/derived.rs` | verifier's batch-weight seed | B | randomness inside the verifier; never shown to anyone |
| shekyl/fcmp-pp-batch-weights-v1 | `rust/shekyl-fcmp/src/batch_weights.rs` | FCMP++ batch-weight seed | A | includes `tree_root` |
| shekyl/fcmp-membership-only-batch-weights-v1 | `rust/shekyl-fcmp/src/batch_weights.rs` | membership-only batch-weight seed | A | includes `tree_root` |

### A.2 Mechanism 2: HKDF salt and info

| Domain | Where | What it hashes | Class | Why |
|---|---|---|---|---|
| shekyl-kem-v1 (salt) | `rust/shekyl-crypto-pq/src/kem.rs` | combines the X25519 and ML-KEM shared secrets | B | per-output secret |
| shekyl-seed-normalize-v1 (salt) | `rust/shekyl-crypto-pq/src/account.rs` | seed → 64-byte master seed | B | local intermediate; every consumer then expands under `salt_for` |
| shekyl-master-derive-v2- (salt prefix) | `rust/shekyl-crypto-pq/src/account.rs` | the wallet-key HKDF salt | A | prefix plus `net.tag()` |
| shekyl-output-derive-v1 (salt) | `rust/shekyl-crypto-pq/src/derivation.rs` | per-output secrets from combined_ss | B | per-output secret that ends up in one tx |
| shekyl-view-tag-prefilter-v1 (salt) | `rust/shekyl-crypto-pq/src/derivation.rs` | wire view-tag byte | B | per-output |
| shekyl-output-kem-v1 (salt) | `rust/shekyl-crypto-pq/src/derivation.rs` | sender's KEM seed from tx_key | B | sender-local |
| shekyl-view-tag-x25519-v1 (salt) | `rust/shekyl-crypto-pq/src/derivation.rs` | counterfactual view tag | B | only `examples/fa6_decap_prefilter_gate.rs` calls it |
| shekyl-ed25519-spend | `rust/shekyl-crypto-pq/src/account.rs` | spend scalar | A | salt = `salt_for(net)` |
| shekyl-ed25519-view | `rust/shekyl-crypto-pq/src/account.rs` | view scalar | A | same |
| shekyl-ml-kem-768 | `rust/shekyl-crypto-pq/src/account.rs` | ML-KEM d_z | A | same |
| shekyl-output-x / -y / -mask / -amount-key / -view-tag-combined / -amount-tag / -label-key / -label-tag / shekyl-pqc-output / shekyl-pqc-ed25519 (10 rows) | `rust/shekyl-crypto-pq/src/derivation.rs` | per-output secrets (key offsets, mask, amount, tags, label, PQC keypair seed) | B ×10 | expanded from combined_ss; land in one tx |
| shekyl-pqc-leaf-blind | `rust/shekyl-crypto-pq/src/leaf_commitment.rs` | leaf blind r | B | per-output |
| shekyl-pqc-leaf-record-blind | `rust/shekyl-crypto-pq/src/leaf_commitment.rs` | record blind r_h | B | per-output |
| shekyl-view-tag-prefilter (info) | `rust/shekyl-crypto-pq/src/derivation.rs` | view-tag byte | B | per-output |
| shekyl-view-tag-x25519 (info) | `rust/shekyl-crypto-pq/src/derivation.rs` | counterfactual tag | B | example-only |
| shekyl-archival-p-{ed25519-spend, ed25519-view, ml-kem-768, ed25519-account-sign, ml-dsa-65, bond-spend-ed25519, bond-spend-ml-dsa-65, hs-id-ed25519, receipt-ed25519, receipt-fn-dsa-1024}-v1 (10 rows) | `rust/shekyl-crypto-pq/src/archival_p.rs` | persona P's key seeds per slot | A ×10 | salt = `salt_for(net)` |
| shekyl-v31-{hybrid-sign, classical-spend, view-tag, kem-seed, multisig-kem} (5 rows) | `rust/shekyl-crypto-pq/src/multisig_receiving.rs` | per-output multisig material from KEM secrets | B ×5 | per-output secrets |
| shekyl/msg-sign-seed-slh-dsa-192s-v1 | `rust/shekyl-crypto-pq/src/message_signing.rs` | message-signing identity seed | A | salt = `salt_for(network)` |
| shekyl-prefs-hmac-v1 | `rust/shekyl-engine-prefs/src/hmac_key.rs` | prefs HMAC key from file_kek | B | local file |
| shekyl-region1-aead-v2 | `rust/shekyl-crypto-pq/src/wallet_envelope.rs` | wallet-file region 1 key | B | local |
| shekyl-region2-aead-v2 | `rust/shekyl-crypto-pq/src/wallet_envelope.rs` | wallet-file region 2 key | B | local |
| nonce | `rust/shekyl-multisig/src/encryption.rs` | AEAD nonce for multisig group messages | B | secret shared only within the group |

### A.3 Mechanism 3: FROST transcript

| Domain | Where | What it hashes | Class | Why |
|---|---|---|---|---|
| Shekyl FROST SAL v1 | `rust/shekyl-fcmp/src/frost_sal.rs` | root of the multisig SAL transcript over `signable_tx_hash` | B (NI-F12) | `signable_tx_hash` is the prefix hash, with no chain data; bound by the tx's membership proof and `reference_block` |
| SpendAuthAndLinkability Multisig | `rust/shekyl-fcmp-proofs/src/sal/multisig.rs` | inherited sub-domain | B (NI-F12) | same; frozen |
| FROST-ED25519-FCMP++-v1 | `rust/shekyl-fcmp-proofs/src/sal/multisig.rs` | ciphersuite CONTEXT | B | constant, used only inside the signing group |
| Ed25519 Monero T | `rust/shekyl-fcmp-proofs/src/sal/multisig.rs` | ciphersuite ID | B | same |

### A.4 Mechanism 4: Blake2b

| Domain | Where | What it hashes | Class | Why |
|---|---|---|---|---|
| Shekyl FCMP++ SAL full v1 | `rust/shekyl-fcmp-proofs/src/sal/mod.rs` | SAL challenge: `signable_tx_hash`, input, L, … | B (NI-F12) | prefix hash only; tied to the chain through the FCMP++ proof against the tree at `reference_block` |
| Shekyl FCMP++ SAL membership-only v1 | `rust/shekyl-fcmp-proofs/src/sal/mod.rs` | membership-only challenge | B (NI-F12) | same |
| Shekyl FCMP++ MO nonce {r_o, r_i, r_r_i, r_c, alpha, r_y} v1 (6 rows) | `rust/shekyl-fcmp-proofs/src/sal/membership_only.rs` | hedged prover nonces | B ×6 | prover-internal secrets |

### A.5 Mechanism 5: Keccak and Schnorr

| Domain | Where | What it hashes | Class | Why |
|---|---|---|---|---|
| shekyl-outbound-tx-proof-v1 | `rust/shekyl-proofs/src/tx_proof.rs` | Schnorr over txid, address bytes, message, per-output data | A | txid, and the address bytes start with the network id (NI-R15); proof version 2 |
| shekyl-inbound-tx-proof-v1 | `rust/shekyl-proofs/src/tx_proof.rs` | same | A | the same |
| shekyl-reserve-proof-v1 | `rust/shekyl-proofs/src/reserve_proof.rs` | Schnorr over address bytes, message, per-output data | A | `canonical_address_bytes` starts with the network id (`rust/shekyl-engine-core/src/engine/proofs.rs`; NI-R15: proved against the chain, so the id); proof version 2 |
| shekyl-reserve-proof-dleq-v1 | `rust/shekyl-proofs/src/dleq.rs` | DLEQ over address bytes, message, output_key | A | the same address bytes (NI-R15) |
| shekyl/msg-sign-outer-v1 | `rust/shekyl-crypto-pq/src/message_signing.rs` | classical Schnorr over the preimage and σ_pq | A | signs the preimage, which carries the id |
| `shekyl-subaddr-v1\0` | `rust/shekyl-crypto-pq/src/output_claim.rs` | m_i from view_scalar and index | A | the view scalar is name-salted |
| Monero Generator T / FCMP++ Generator U / V / Helios / Selene initializers (5 rows) | `rust/shekyl-curve-generators/src/lib.rs` | fixed public generators | B ×5 | public parameters with no message; frozen, so they could never take the id anyway |
| bulletproof / bulletproof_plus | `rust/shekyl-bulletproofs/build.rs` | BP generators | B ×2 | public parameters |
| bulletproof_plus_transcript | `rust/shekyl-bulletproofs/src/plus/transcript.rs` | BP+ transcript initializer | B | constant; the proofs sit inside a tx |

### A.6 Mechanism 6: SHA3-256

| Domain | Where | What it hashes | Class | Why |
|---|---|---|---|---|
| shekyl-mlkem-chacha-seed | `rust/shekyl-crypto-pq/src/account.rs` | ChaCha seed from d_z | A | d_z is derived under `salt_for` |

### A.7 Mechanism 7: Noise BLAKE2s

| Domain | Where | What it hashes | Class | Why |
|---|---|---|---|---|
| shekyl/rpc-channel-v1 | `rust/shekyl-rpc-channel/src/lib.rs` | RPC handshake prologue | A | label followed by the network id |
| shekyl/rpc-busy-v1 | `rust/shekyl-rpc-channel/src/lib.rs` | busy reply MAC | B | keyed by the daemon bundle and answers one message 1 |
| shekyl/rpc-mac1-v1 | `rust/shekyl-rpc-channel/src/lib.rs` | mac1 key over the daemon bundle | B | DoS cookie; the handshake behind it binds the id |
| shekyl/noise-record-header-v1 | `rust/shekyl-noise/src/classed.rs` | header-protection key from the record key | A | the record key comes from a handshake whose prologue is the id |

### A.8 Rulings, and the one brought back

1. **NI-F11 — RULED NI-R14, built.** The emission auth input is `network_id ‖ framed inventory`, the labels `-v3`; `EMISSION_AUTH_MSG_V1` pins each network's digests, `scripts/kat/emission_auth_msg_oracle.py` recomputes them, and the KAT goes red if the id is dropped. The verifier takes the id from its trust through `tx_against` (CEN-J25).
2. **NI-F12 — brought back: the SAL and FROST transcripts do not commit to the network id.** The ruling's premise was that SAL proves over a hash NI-Q4 made network-bound. It does not: SAL's message is the transaction's **prefix hash** (`tx_prefix_hash_for_signing`, `FCMP_SPEND_SIGNING_PREIMAGE.md` §1.2), and the FROST transcript proves over the same `signable_tx_hash`; NI-Q4 put the id into a different hash, the per-input PQC `signed_hash(i)`. What binds them is enclosure, in the other direction: `payload(i)` holds the prefix, the ct base (with `reference_block`) and `prunable_hash`, the hash of the blob that carries the FCMP++ proof, SAL included, and every spend input carries a PQC auth over the network-bound hash (CEN-I18). The network-bound signature covers the SAL proof; the SAL proof does not cover the network. A replayed transaction is refused at CEN-I18, and its SAL verifies under any id. Two ways forward, for Rick: **(a)** record the four rows as bound by enclosure, with a test that the same transaction, whose SAL verifies on both networks, is refused under the other id at CEN-I18; **(b)** pass a network-bound signable hash into SAL at the builder and the verifier (the vendored proof code untouched), a consensus change to what every spend, FROST multisig and emission backing proof proves over. Neither is built.
3. **NI-F13 — RULED NI-R15, built.** The proofs' address bytes start with the network id (tx and reserve proofs share them; both proof versions are 2, a version-1 proof refused by name). The multisig fingerprint's input starts with the network's name, length-prefixed (`-v2`); `MULTISIG_FINGERPRINT_V2.json` pins each network's, `scripts/kat/multisig_fingerprint_oracle.py` rebuilds them.
4. **Placement — RULED NI-R13.** The id is in the hash input at a fixed position, for spend and message signing alike, and for every hash above.

### A.9 Registry rows with no production caller

These are `shekyl-live`, but nothing in a shipped path calls them. Each is classed above as its code reads; whether its status should change is not this round's question:

- `shekyl/archival-serve-credit-batch-v1`: nothing consumes it.
- `shekyl/archival-witness-carrier-scheme-v1`: called only from `#[cfg(test)]` code in `fn_dsa_hybrid.rs`.
- `shekyl-subaddr-v1\0`: its module says it has no V3.0 production caller.
- The `shekyl-view-tag-x25519-v1` salt and its info label: called only from an `examples/` binary.
- `shekyl/pqc-auth-tx-multisig-v1` and the five `shekyl-v31-*` rows: their production signer and constructor are not built yet.
