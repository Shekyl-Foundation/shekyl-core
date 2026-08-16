# Genesis Allocations

The complete, verifiable record of what genesis creates on each Shekyl
network: who receives it, how much, and how to rebuild the exact bytes
pinned in the source. This document fulfils the commitment made in
[`GENESIS_TRANSPARENCY.md`](GENESIS_TRANSPARENCY.md) §5.

Every figure here is checkable against the repository — nothing below is a
claim you have to take on trust. See [Reproducing genesis](#reproducing-genesis).

---

## 1. Summary

| | |
|---|---|
| Recipients per network | 5 |
| Allocation each | 20,000 SHEKYL (`20,000,000,000,000` atomic) |
| Total at genesis | 100,000 SHEKYL (`100,000,000,000,000` atomic) |
| Share of the 2^32 supply ceiling | 0.002329% |
| Foundation allocation | none |
| Premine beyond the above | none |

Amounts use the full currency name **SHEKYL** (the ticker SKL is not used
in this document). Genesis is the only block whose contents are not earned
by proof of work, and it is deliberately small, equal, and public. All five
allocations are identical; there is no tiered or preferential distribution.
The remaining 99.997671% of all SHEKYL that will ever exist must be mined.

Genesis outputs carry **cleartext amounts** (CT type Null) — unlike every
later transaction, they are not confidential. That is intentional: the
founding allocation is auditable by anyone, forever. Once spent, these
outputs receive exactly the same FCMP++ membership privacy as any other
output; the transparency is scoped to the allocation itself.

## 2. Allocations

### mainnet

Source of truth: [`config/genesis_recipients.mainnet.json`](../config/genesis_recipients.mainnet.json)

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Founder allocation 1 | 20,000 SHEKYL | `shekyl1q9y7r7cn8…xqjudqx2ex3q` |
| 2 | Founder allocation 2 | 20,000 SHEKYL | `shekyl1q8slynhua…mz3c8s48rrt0` |
| 3 | Founder allocation 3 | 20,000 SHEKYL | `shekyl1q9g0g2vmt…9epsysdwr77m` |
| 4 | Founder allocation 4 | 20,000 SHEKYL | `shekyl1qyuvwck4v…z32unsvq9jqx` |
| 5 | Founder allocation 5 | 20,000 SHEKYL | `shekyl1qypaqfqxf…leqzus5pdly4` |

Genesis identity:

```text
GENESIS_NONCE  10000
tx hash        7d578c228f117681e20c225527fdf54593beafd693ec1dc08ebe020188baf573
block id       49d3831cb7212fbbeae14c341d1cf6667ddbf28952f76668b8b569d5fb2e2ab0
```

### stagenet

Source of truth: [`config/genesis_recipients.stagenet.json`](../config/genesis_recipients.stagenet.json)

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Founder allocation 1 | 20,000 SHEKYL | `sshekyl1q8tpl0cj…00568qam38dc` |
| 2 | Founder allocation 2 | 20,000 SHEKYL | `sshekyl1q9fet8jh…4cy77qkxahm5` |
| 3 | Founder allocation 3 | 20,000 SHEKYL | `sshekyl1qy69mmkk…xad49sykauun` |
| 4 | Founder allocation 4 | 20,000 SHEKYL | `sshekyl1q92cx59c…lahv3s2z5yst` |
| 5 | Founder allocation 5 | 20,000 SHEKYL | `sshekyl1qyspctq2…tw5cwsqk2u2q` |

Genesis identity:

```text
GENESIS_NONCE  10002
tx hash        7e7a757b1d907f19d7b5bdf233edf7ece9446979b834af937fc7fedf0678c4a1
block id       e5683ca39b1ce002cd08fd7c1b467110f31daa1560db6cc7bb6bf1b1f2c1a11a
```

### testnet

Source of truth: [`config/genesis_recipients.testnet.json`](../config/genesis_recipients.testnet.json)

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Developer 1 | 20,000 SHEKYL | `tshekyl1q849z9k4…7qun4s3prjf4` |
| 2 | Developer 2 | 20,000 SHEKYL | `tshekyl1q9c7ffkn…yhzf4q5qx6yq` |
| 3 | Developer 3 | 20,000 SHEKYL | `tshekyl1qxrg5vxx…2fg0zs9x74gn` |
| 4 | Developer 4 | 20,000 SHEKYL | `tshekyl1q9h4aw68…0lkhnszd0epx` |
| 5 | Developer 5 | 20,000 SHEKYL | `tshekyl1q8eagpjh…qnn9fq4jnkjy` |

Genesis identity:

```text
GENESIS_NONCE  10101
tx hash        f450491a2e41fa5e574fa3c5af1438f77524f657a843f9d5f52afeab312f618a
block id       3dcfcd97ffed5f9b474a5edbaa23cb03bc8f7d7bc41570aab66f9111e66773e9
```

Addresses are truncated above for readability only — the full strings are
in the linked JSON files, which are the bytes genesis actually commits to.
The 2026-08-16 fork-(ii) re-encode kept each recipient's spend/view/ek and
filled `msg_sign_pk` so the files parse on the current layout; the freeze
ceremony (`geblock gen-wallets`) still replaces this set with seed-derived
keys.
Each address is a three-segment Bech32m string
(`<classical>/<ML-KEM part A>/<ML-KEM part B>`) carrying the hybrid
post-quantum key material Shekyl requires from genesis.

## 3. Reproducing genesis

The genesis transaction key is **derived deterministically from the
recipients file**, so the pinned `GENESIS_TX` is reproducible by anyone —
you do not have to trust that the published addresses are the ones actually
paid. From a checkout at the commit that pins this genesis:

```bash
cd rust
cargo run -p shekyl-genesis-tool --bin geblock -- verify
cargo run -p shekyl-genesis-tool --bin geblock -- block-id --network mainnet
```

`verify` rebuilds all three networks from the committed recipients files and
byte-compares the result against the `GENESIS_TX` strings in
[`src/cryptonote_config.h`](../src/cryptonote_config.h); `block-id` prints
the block identity to check against the table above. CI runs the same
byte-compare on every change
(`rust/shekyl-genesis-tool/tests/config_pin_gate.rs`), so the pins and the
published recipients cannot drift apart unnoticed.

### Why the transaction key is public

Genesis publishes its amounts and its recipients by design, so a genesis
transaction key protects nothing: its jobs — amount privacy and recipient
unlinkability — are deliberately absent at height 0. It also cannot spend:
moving these funds requires the recipients' secret spend keys and an FCMP++
membership proof. Deriving it publicly therefore discloses nothing this
document does not already state, and buys full reproducibility of the
founding block.

Derivation (implemented in `rust/shekyl-genesis-tool/src/txkey.rs`):

```text
M = varint(len(net)) ‖ net_ascii            net ∈ {mainnet, testnet, stagenet}
    ‖ varint(n_recipients)
    ‖ for each recipient, in file order:
        varint(len(addr)) ‖ addr_utf8       canonical full address
        ‖ amount_atomic as u64 little-endian

seed      = cSHAKE256-32(customization = "shekyl/genesis-txkey-v1", input = M)
tx_secret = seed reduced mod ℓ
tx_pub    = tx_secret · G                   (the tx_extra 0x01 field)
```

## 4. Key custody

The recipient wallets were generated with fresh operating-system entropy
(`geblock gen-wallets`), one seed per wallet, captured once at generation:
24-word BIP-39 mnemonics on mainnet and stagenet, 32-byte seeds on testnet.
No component of the Shekyl stack can re-export a seed after creation, and
each wallet was restore-verified from its written seed before its address
was committed here.

Only public addresses appear in this repository. Seed material has never
been committed to any repository and is held offline by the individual
recipients.

## 5. Change policy

Genesis is frozen at launch: after the first block is mined on a network,
its allocations cannot change. Before launch, any change to this table
means regenerating the genesis transaction and re-pinning every derived
artifact together — the procedure is
`shekyl-dev/docs/GENESIS_WALKTHROUGH.md`. `NETWORK_ID` and `GENESIS_NONCE`
are unchanged by allocation edits.
