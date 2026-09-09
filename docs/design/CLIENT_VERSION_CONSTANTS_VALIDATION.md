# VC — Client-side version and constants validation

**Status:** OPEN — design round 2. **Review rounds 1 and 2 (§8, §9) raised
`VC-R1`…`VC-R12`; all twelve are ruled and applied.** `VC-R2` and `VC-R3`
were upheld — the genesis axis moved onto `get_version`, and the fakechain
operator flag is rejected outright rather than defaulted off.
**The §6 rulings are SIGNED in-channel by Rick (2026-09-07).** They were
first recorded from a relay on 2026-09-06 with the provenance stated as a
relay rather than a signature; that caveat is now discharged, and §7 keeps
the sequence because the discipline is what produced the correction, not the
outcome. `VC-1` is built in the PR that lands
this document, widened to both integer authorities under `config/` per
ruling 5 (`VC-D12`). **`VC-2`, `VC-3` and `VC-4` are authorised for alpha.8,
folded into one PR** (ruling 2), and are not started; that PR's first
paragraph must state all four axes. Every `file:line` below was read at
`dev` = `2dba46537` (PR #619, RK-5b merge); the anchor for `VC-1`'s landing
is `262c06ba9`.
**Identifier family:** `VC-` (version and constants validation), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in the commit that
lands this document (rule 94). `VC-D*` are dispositions of this round;
`VC-1`…`VC-4` are the implementation slices §4 names. Neighbours checked:
`CV-` (cover traffic) is taken and is a different family; `VC-`, `CDG-` and
`HS-` were free at the anchor.
**Parent:** [`DAEMON_RPC_KV_CUTOVER.md`](DAEMON_RPC_KV_CUTOVER.md) §7, the
2026-09-04 rows that found both facts below and named this round without
building it.
**Process rule:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
is invoked: multi-round, crosses the FFI boundary (`VC-2` widens the chain
facts POD) and the wire (`VC-2` bumps `CORE_RPC_VERSION`), and touches
consensus-adjacent constants. `VC-2` gets a pre-flight pass before code.
**Decision authority:** Rick. §6 lists the rulings and their state.

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
privacy is the product, and a wallet that scans a daemon on a different
chain or a different network shows its owner a balance that is not theirs;
the system must outlast the team, and a published fact nobody reads is
maintenance with no consumer. This round trades nothing in security: the
check refuses, and refusing is the safe direction on every arm (§3.6).

---

## 0. Problem statement, verified at source

Two published facts on the daemon's RPC surface have no consumer. Both were
found during RK-5b; both were re-swept for this document rather than
inherited, because a negative claim inherits well and verifies badly.

### 0.1 `CORE_RPC_VERSION` is read by nobody

The unfiltered sweep, run at the anchor — **not** narrowed by expected
phrasing, per the 2026-09-04 lesson that a filtered sweep reports clean for
exactly the cases it was written not to match:

```
grep -rn "CORE_RPC_VERSION" rust/ src/ tests/ utils/ \
  --include=*.rs --include=*.cpp --include=*.h --include=*.py | grep -v target/
```

31 hits, every one read:

| Hits | What they are |
| --- | --- |
| 1 | The producer: `rust/shekyl-daemon-rpc/src/methods.rs:129` fills `GetVersionResponse.version`. |
| 2 | The producer's own unit test (`methods.rs:1852`, `:1873`) asserts the reply carries the constant. |
| 4 | The constant's definition: `rust/shekyl-rpc-types/src/chain.rs:44`, `:80`, `:81`, `:82` (major, minor, the packing formula). |
| 4 | The constant's pins: `chain.rs:383–386` (packed value, packing expression, major, minor — the 2026-09-04 merge-safety fix). |
| 11 | The oracle-vector parity and chain-delta tests in `rust/shekyl-rpc-types/tests/rpc_parity.rs`. |
| 2 | The re-export, `rust/shekyl-rpc-types/src/lib.rs:82–83`. |
| 7 | Comments and doc comments (`chain.rs:41`, `:45`, `:338`, `:367`; `headers.rs:16`; `src/rpc/core_rpc_server_commands_defs.h:84`, `:89`). |

**Zero hits compare the constant to a value that came off the wire.** Not
`shekyl-daemon-rpc/src/console/` (the `shekyld <command>` arm), not
`shekyl-rpc-client`, not `shekyl-engine-core`'s daemon client, not
`shekyl-cli`'s. The `version` field is produced, versioned, pinned, chained
across four oracle vectors and delta-tested at every link — and changes
nobody's behaviour. This is the *correct mechanism with no consumer* class
the parent's §7 named on 2026-09-04.

### 0.2 `get_info.nettype` is read by nobody either — and a plan lock says it is

The C++ `on_get_info` fills `nettype` as one of `"mainnet"`, `"testnet"`,
`"stagenet"`, `"fakechain"` (`src/rpc/core_rpc_server.cpp:237`). No Rust
client reads it: `grep -rn nettype rust/shekyl-engine-core/src
rust/shekyl-wallet-rpc/src rust/shekyl-cli/src rust/shekyl-daemon-rpc/src/console`
returns nothing outside tests. `rust/shekyl-rpc-types` has no `nettype`
anywhere — `get_info` is still a bridged C++ leg (RK-5c's).

That would be a second instance of §0.1, except that this one was
**required**. [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) :216,
cross-cutting lock 5:

> `Wallet::open` requires a `DaemonRpcClient` whose declared network
> matches; mismatch is `OpenError::NetworkMismatch`, never a warning. The
> daemon URL's network is **verified via `get_info` before any wallet
> operation** — defends against DNS hijack pointing a testnet wallet at a
> mainnet daemon.

What landed is half of that. `OpenError::NetworkMismatch`
(`rust/shekyl-engine-core/src/engine/error/lifecycle.rs:52`) is raised from
`lifecycle/support.rs:53` by translating `WalletFileError::NetworkMismatch` —
the **wallet file's** declared network against the caller's `expected`
parameter. The daemon is never asked — the variant's own shape,
`{ wallet, expected }`, has no field for a daemon-reported value, so the type
could not implement the lock even if a call site wanted to. And two
docstrings say the opposite of what the code does. `engine/daemon.rs:169`:

> Daemon network verification is performed by `Engine::open_*` against the
> on-disk wallet file's network declaration.

— literally true about what it does, while its subject says "daemon network
verification"; a reader takes the subject. And `engine/error/mod.rs:41`,
under "variant names locked in by the plan":

> `OpenError::NetworkMismatch` — wallet file says network N, daemon client
> says network M.

Both are *prose claims asserted rather than tested* — the second of the
three defect shapes RK-5b's six review rounds catalogued — and both have been
standing since Phase 1. `VC-4` corrects both in the same PR as the check;
prose that is load-bearing-false does not get a follow-up.

The regtest end-to-end suite (`engine/regtest_e2e.rs`) opens `Network::Mainnet` wallets against a
`shekyld --regtest` daemon that reports `"fakechain"`, and passes, which is
the proof: the check does not exist, so nothing has ever had to accommodate
it (§3.6.4 is where that accommodation is designed).

### 0.3 The one client-side constants check that exists is narrow by design

`rust/shekyl-daemon-rpc/src/console/info.rs:117` (`daa_target_seconds`)
compares `/get_info`'s `target` against the build's own
`crate::consensus::DAA_TARGET_SECONDS` and *warns*, rendering from the
build's value. RK-5b wrote it that narrow on purpose and said so in the
function's doc comment: "the general instrument … is a separate round; it is
not built here". This is that round. `VC-D11` rules what happens to the
narrow check when the general one lands.

### 0.4 Who acts differently because of a published fact

That is the question this round exists to answer, and today the answer is
"nobody". The table is what that leaves open, per axis of difference between
a client's build and the daemon it dials:

| Client and daemon differ in | What happens today | Why it matters |
| --- | --- | --- |
| **Wire shape** (`CORE_RPC_VERSION`) | A renamed or removed field fails `deny_unknown_fields` deserialisation at the first method that reads it, with a message naming a field, not a version. An *omitted* field with `#[serde(default)]` becomes its zero **silently** — the open FOLLOWUPS item "`#[serde(default)]` still lets an omitted daemon field become its zero value", 27 fields. | A late, per-method, badly-worded failure at best; a confident zero at worst. |
| **Consensus rules** (`config/consensus_constants.json`) with the same wire shape | Nothing. Every method parses. The console prints statistics from a different chain; the wallet scans and shows a balance computed under different rules. Only `T` gets a warning (§0.3). | A daemon rebuilt from a different constants file *is a different chain* wearing the same RPC contract. |
| **Network** (`mainnet` / `testnet` / `stagenet` / `fakechain`) | Nothing. A testnet wallet pointed at a mainnet daemon — the lock-5 DNS-hijack case, verbatim — scans mainnet. | The plan ruled this a typed refusal in Phase 1; it never landed. |

Three axes, three different failures, three different messages an operator
needs. That is why §2 does not collapse them into one "handshake".

**And the wrong-chain daemon is undefended twice over, today.** The lock-5
attack — a wallet pointed at a daemon on a different chain — has no network
check (§0.2) *and* no genesis check: no Rust pin of a genesis block hash
exists and no client compares block 0's hash to anything (found 2026-09-05
while grounding `VC-D12`; §2's genesis row). Three stated commitments were
chased on this day and all three lacked an enforcing site — the plan's
"verified via `get_info`", this document's own first draft's "committed to
by the genesis block hash", and, in another lane, `GENESIS_TX_WIRE_FORMAT`'s
"consensus parses `32·n_outputs`". The identity tuple is the enforcing site
for the first two.

---

## 1. Threat model — what this check is, and what it is not

**T, named:** a client dialing a daemon that is *honestly different* from the
one the client was built for. Instances: a stale binary on one side after a
rebuild; an operator's `--daemon-address` pointing at the wrong node; a DNS
answer that moved (lock 5's case); a daemon rebuilt from an edited
`config/consensus_constants.json`; a `--testnet` daemon behind a mainnet URL.
**Channel:** the RPC reply itself. The daemon states its version, rules
digest and network; the client compares each to its own compiled value.

**What this is not.** It is not authentication. A daemon that *wants* to lie
reports whatever the client expects — the digest is a label the daemon
attaches to itself, not a proof of the rules it runs. A mismatch is proof of
difference; a match is evidence, not proof, of sameness. Trust in the peer
and in the path is the transport posture's job
([`RT-`](IMPLEMENTATION_INDEX.md) family; every RPC leg is operator-to-
operator, the adversary is the network path). This round adds nothing to
that and takes nothing from it — it makes the *honest* mismatch, which is by
far the common case, fail early, loudly and by name instead of late, quietly
and by symptom.

**Why refusing is safe on every arm (§3.6).** The client's alternative to
refusing is to proceed against a daemon it has just proved is different. On
the rules axis that means rendering or scanning a different chain; on the
network axis it means the lock-5 case; on the wire axis it means the
`#[serde(default)]` zero. There is no arm where proceeding is better than
stopping, so there is no arm that needs a "warn and continue" mode — and a
mode that exists gets used ([`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc):
optionality without a concrete need is debt).

---

## 2. The identity tuple

A client establishes, once per connection, that the daemon it dialed is the
daemon it was built for, on independent axes (three at the round's opening,
four after `VC-D12`):

| Axis | Client's value | Daemon's value | Mismatch means |
| --- | --- | --- | --- |
| **Wire** | compiled `CORE_RPC_VERSION` | `get_version.version` | the two binaries do not share an RPC contract; every reply is suspect |
| **Rules** | compiled `CONSENSUS_CONSTANTS_DIGEST` (§3.3) | `get_version.consensus_constants_digest` (new, `VC-D5`) | the two binaries were built from different consensus constants; this is a different chain |
| **Network** | the wallet's `Network` / the console's caller | `get_version.nettype` (new, `VC-D5`) | same rules, different instance of them |
| **Genesis** (`VC-D12`) | a per-network pinned genesis block hash, new in Rust | `get_version.genesis_hash` (new; **moved off `on_get_block_hash([0])` by `VC-R2`**) | the daemon's chain does not start where this build's does: a different chain, whatever else agrees |

The genesis axis was added when `VC-D12`'s first draft excluded the
`genesis_recipients.*.json` files from the digest on the ground that "the
genesis block hash already commits to them" — and the steering lane checked
whether anything compares that hash. Nothing does: no Rust pin of a genesis
hash exists and no client reads block 0's hash. The daemon pins
`GENESIS_TX` / `GENESIS_NONCE` per network in `src/cryptonote_config.h:368`
(and `:500`, `:511`); the client side has never held the answer. So the
axis joins the tuple rather than serving as an excuse — and it is carried in
`get_version` with the other three (`VC-R2`, ruled 2026-09-07), not on a
second call. Genesis does not replace network: `FAKECHAIN` takes
mainnet's configuration (`cryptonote_config.h:562`), so a regtest daemon
shares mainnet's genesis and only `nettype` tells them apart; and `nettype`
is the value an operator can read in a refusal. Genesis is the strong check;
network is the discriminator and the message.

Two things follow from `FAKECHAIN` taking mainnet's configuration, stated so
a later reader does not file either as a defect. First, it is rule 71
([`71-network-uniformity`](../../.cursor/rules/71-network-uniformity.mdc))
working exactly as written: the network selects *data* — `FAKECHAIN` selects
mainnet's constants, `GENESIS_TX` and `GENESIS_NONCE` included — and no
control flow diverges on the consensus surface. Second, and this is why the
tuple has several axes rather than one strong one: **the genesis axis has a
structural blind spot exactly where regtest lives, and only the network axis
sees there.** The axes do not merely add confidence to one another; they
cover different failure sets. Wire skew is invisible to every axis but the
first; a rebuilt constants file is invisible to every axis but the second; a
regtest daemon behind a mainnet URL is invisible to the genesis axis and
caught by the third; a daemon on a different chain with the same constants
and network is caught only by the fourth. That coverage difference is the
justification for the tuple's shape — not "defence in depth", which is what
one writes when the difference cannot be named.

The axes are orthogonal and are kept that way in the refusal: the operator
reads *which* axis failed and what each side's value was. "Wrong daemon" is
not an error message; "this daemon runs testnet, this wallet is mainnet" is.

Rules and network are both needed for chain identity. The constants file has
**no per-network data** — one JSON generates every network's constants — so
the digest is identical across mainnet, testnet and stagenet. The parent's §7
sketch called the digest "stronger than a network-ID byte"; the precise
statement is that it is *orthogonal* to one. The digest says "same rules";
the network says "same instance"; a chain is both.

---

## 3. Dispositions

Each is proposed. Rick rules; the round closes when §6 is empty.

### 3.1 `VC-D1` — the wire handshake: strict equality, and it is forced, not chosen

**RULED with `VC-D5` (ruling 1, 2026-09-06, relayed).** As proposed: a client refuses a daemon whose `get_version.version` differs
from its compiled `CORE_RPC_VERSION` in either component, and its message
names which side is older (`daemon 3.27 < client 3.28: the daemon is the
older build` and the converse).

**Why strict and not a compatibility window.** The wire is *already* exact.
Every reply type in `shekyl-rpc-types` carries `#[serde(deny_unknown_fields)]`
(RK-4c's ruling), so a client tolerating a newer daemon's minor bump would
still fail to parse the field that bump added. A window would be a promise
the types cannot keep. Pre-genesis there is also no external consumer to
promise anything to (`RK-D8`). Strict equality is the only policy consistent
with the types as they stand; choosing anything else here would be choosing
it for the types too, which is not this round's to do.

**Reopening criterion:** a post-genesis compatibility window is wanted. That
round must rule `deny_unknown_fields` and the version policy *together*, and
must first close the `#[serde(default)]` FOLLOWUPS item, because a window
across an omitted field is a window across a silent zero.

### 3.2 `VC-D2` — the rules digest: subject is the whole file, not a list

**Ruled (ruling 5, signed in-channel 2026-09-07):** a digest over the
canonical form (§3.3) of **both `config/` integer authorities**, computed at
build time, exposed by the daemon, compared by the client.

**Rejected alternative A — a per-constant comparison** (`target`, then
`daa_window_n`, then …). Its subject is whatever someone listed. A constant
added next year is uncovered until someone remembers; a constant removed
leaves a comparison of nothing against nothing. The RK-5b lesson (rule 47,
[`47-gate-subject-assertion`](../../.cursor/rules/47-gate-subject-assertion.mdc))
is that a check's subject can silently empty; the digest's subject is the
file and cannot.

**Rejected alternative B — a hash of the file's raw bytes.** Its subject is
too large: a comment edit, a whitespace change or a CRLF introduced by an
editor moves the digest and every client refuses every daemon over a change
to nothing. The 2026-09-05 CRLF row in the parent's §7 is the cautionary
instance. The canonical form exists to make the digest's subject exactly the
constants.

**The argument for the digest, stated once.** It is derive-don't-hardcode
applied to the check itself: the check is derived from the authority rather
than from a hand-maintained enumeration of it.

### 3.3 `VC-D3` — canonicalisation, pinned

Both sides must hash identical bytes or the digest is a false-alarm
generator. The rules, in full (canonical form **`v2`**, after `VC-D12` widened
the file set; `v1` was `consensus_constants.json` alone and never shipped):

0. The form opens with the header line
   `shekyl-consensus-constants-canonical-v2` + LF, and then, **per file in
   the fixed order `config/consensus_constants.json`,
   `config/economics_params.json`**, a section line `= <path>` + LF followed
   by that file's lines per rules 1–5. Which file a constant lives in is part
   of the binding, exactly as its key is: swapping two documents between
   their section names is a different digest.
1. Parse the file as JSON. Parse failure fails the build, naming the file.
2. Drop every key whose name begins with `_`. These are the file's prose
   (`_comment`, `_comment_daa`, …: 9 of 31 keys at the anchor).
3. Every remaining value **must be a JSON integer**. At the anchor all 22
   are. A string, boolean, float, array, object or null under a
   non-underscore key **fails the build** with the key named. This is
   enforced rather than assumed: the simplicity of the form below depends
   on it, and the generator is where a future non-integer constant is
   caught and this section is reopened.
4. Sort the remaining keys **bytewise ascending** (not locale, not
   case-insensitive). Key names are ASCII `[a-z0-9_]` at the anchor; a
   non-ASCII key is not forbidden but is sorted by its UTF-8 bytes.
5. Emit, as UTF-8:
   - (the header and section lines of rule 0 — the header is the domain tag
     ([`30-cryptography`](../../.cursor/rules/30-cryptography.mdc)) and the
     version of the canonical form; changing any rule in this list bumps it)
   - then, per key in sorted order: the key, one ASCII space, the value as
     a **decimal integer with no sign, no leading zeros and no separators**,
     LF. Values are non-negative by construction (the C++ generator already
     range-checks every key to `u8` or `u64`); a negative integer fails the
     build.
6. `CONSENSUS_CONSTANTS_DIGEST` = SHA-256 over those bytes, rendered as 64
   lowercase hexadecimal characters.

Why every choice is the boring one: a line-per-key text form has no
serializer-specific behaviour to disagree about — no float formatting, no
string escaping, no key-quoting, no trailing-comma rules — so a Python
generator and a Rust `build.rs` agree by construction, and the form is
checkable by eye. SHA-256 because `sha2` is already a workspace dependency
and because this is a **label, not a protocol hash**: it authenticates
nothing (§1), so the choice of function carries no security weight and the
domain tag is hygiene, not a separation requirement.

**Two pins land with the computation (`VC-1`):**

- a **canonical-form KAT**: a fixed synthetic JSON (with comment keys,
  unsorted keys, values across the `u8`/`u64` range) and its expected
  canonical bytes and digest, so the *rules* are pinned independently of
  the live file;
- a **live-file pin**: `PINNED_DIGEST` in `build.rs`, compared there so the
  panic can print the computed digest, so a change to either JSON is a
  reviewed change to a Rust source line rather than a silent move of every
  client's refusal. It began as a `const _: () = assert!` beside the
  constant, in the style of `shekyl-daemon-rpc/src/lib.rs`'s Decision-14
  sentinels; `VC-R5` moved it, because that form cannot name the value the
  developer must copy (§8). The panic **branches on what moved** — value,
  rename, or added/removed key — since the single chain question is answered
  "no" by a pure rename and the old wording then pointed at deleting the
  constant (`VC-R13`, §9).

### 3.4 `VC-D4` — one computation, in `shekyl-rpc-types`

The digest must exist in the daemon (to publish) and in every client (to
compare). Where it is computed decides how many copies exist.

| Option | Copies | Verdict |
| --- | --- | --- |
| (a) each consumer's `build.rs` (`shekyl-daemon-rpc`, `shekyl-engine-core`, …) computes it | 2 today, growing | **Rejected.** Three-local-copies-one-wrong is the class this workspace has already paid for; the canonicalisation rules would live in N places. |
| (b) a shared `[build-dependencies]` crate holding the canonicaliser | 1 implementation, N invocations | Workable, but adds a crate whose only job is to be invoked from build scripts. |
| (c) **`shekyl-rpc-types/build.rs`** computes it once and emits `pub const CONSENSUS_CONSTANTS_DIGEST: &str` next to `CORE_RPC_VERSION` | 1 | **Proposed.** Every RPC party — `shekyl-daemon-rpc`, `shekyl-engine-core`, `shekyl-rpc-client` — already depends on this crate; the digest is a wire-contract fact and sits beside the other one. The daemon reads the constant to fill the reply; the client reads the same constant to compare. |

Cost of (c): `shekyl-rpc-types` gains `[build-dependencies] serde_json, sha2`
(both workspace pins) and a `build.rs` that walks to `config/` exactly as
the seven existing generators do. It gains **no** runtime dependency and no
new production surface beyond one `&str`.

**`cmake/generate_consensus_constants.py` does not compute the digest**
(`VC-D9`). Nothing in C++ consumes it: `get_version` is served natively by
Rust since RK-1, and the console's both arms render in Rust. A C++ copy
would be a third implementation of §3.3 with no reader.

### 3.5 `VC-D5` — exposure: `get_version` grows two fields, and the version moves

**RULED (ruling 1, 2026-09-06, relayed): as proposed, with the one-byte FFI
widening — and on a stronger ground than this section had given.** Rick's
reason is **atomicity**: two calls can straddle a restart or a
reconfiguration and return axes from different states, so a client that
handshakes over two methods validates a tuple that never simultaneously
existed. One call, one snapshot, no skew — and half the round trips on a
path every client walks at connect. That argument kills the two-method
alternative outright; the coupling argument below (tying the handshake to
RK-5c's bridged leg) was the weaker one. **Corollary for `VC-4`, as it stood before `VC-R2`:** the
genesis axis was to ride a *second* call (`on_get_block_hash([0])`), so the
tuple would have been atomic across three axes with the genesis hash checked
beside it.
**`VC-R2` found that exemption unsound and it is now gone (ruled
2026-09-07).** The atomicity concern is not whether the *value* can move
between calls but whether the **answerer** can change, which a restart
between calls does, and which a proxy or load balancer fronting two nodes
does as a matter of course — the RT posture ships `--daemon-address`
precisely to support remote daemons, which is where middleboxes live. A
client pairing `get_version` from node A with block 0 from node B accepts a
tuple that never simultaneously existed, which is verbatim the failure
ruling 1 rejected. **The genesis hash is therefore a fourth `get_version`
field**, 32 fixed bytes the daemon already holds, on a wire change already
happening. All four axes are one reply, one snapshot, no skew, and the
exemption does not need defending because it no longer exists.

As proposed: `GetVersionResponse` gains

```
consensus_constants_digest: HashHex  // 32 bytes, 64 lowercase hex (§3.3)
nettype: DaemonNetwork               // "mainnet" | "testnet" | "stagenet" | "fakechain"
genesis_hash: HashHex                // block 0, per network (VC-R2)
```

**The digest is `HashHex`, not `String` (`VC-R16`).** It is a SHA-256: 32
bytes rendered as 64 lowercase hex — the same subject `hash.rs` exists for.
That module's own doc records why: before RK-3 each such field was a `String`,
"which made *not a hash at all* a value the type admitted and left every
consumer to parse hex for itself". A `String` digest would repeat that
exactly, and worse on this field than on most: it would **false-mismatch on
uppercase hex** — reporting a rules disagreement, on the axis whose entire job
is to be precise about rules — and would let `"nope"` reach the comparison as
data rather than being refused at the parse. `HashHex` refuses any length but
64 and any non-hex character, accepts either case on the way in, and re-emits
lowercase, so the strictness `VC-D14` requires is delivered **by the type**
rather than by a rule someone must remember.

**Every one of these three deserializes strictly** — no `#[serde(default)]`,
no catch-all variant, an unrecognised value refuses. That is `VC-D14`
(§3.14), and it is a requirement on this struct rather than a property of
one field.

and `CORE_RPC_VERSION` takes the next free minor. **3.28 was free at this
document's anchor and is NOT free now** — `dev` carries 3.28 with a fifth
`get_version` oracle vector (`VC-R1`, §8), landed by another lane while this
document sat unmerged. The number is therefore stated nowhere in this
document as a value to use. **Read `dev` at the moment `VC-2` is written, not
at the moment it branched** —
3.26 was claimed by two branches on one day and git merged the line clean.
The whole-chain delta test now catches a taken number, but only at merge.

**Why `get_version` and not `get_info`.** `get_version` is the method whose
question is "what am I talking to"; the handshake is that question with two
more parts. It is served natively, has a typed reply and an oracle chain, and
is not about to change for other reasons. `get_info` carries `nettype`
already but is a bridged C++ leg that RK-5c retires and redesigns, has no
Rust reply type yet, and carries ~40 fields the handshake does not want. A
two-method handshake (`get_version` for wire and rules, `get_info` for
network) would need no new `nettype` field but would tie the identity check
to a leg in flight and read its three facts from two replies. One reply, one
chain state, one oracle vector is the property worth paying one duplicated
field for; `get_info.nettype` becomes RK-5c's to keep or retire (RK-W's wire
cleanup is where duplicates die).

**The FFI cost, re-priced (rule 40) — the original estimate was written
before `VC-R2` and nobody revisited it.** It read "one `u8`, one field, both
sides of the boundary in the same slice", and at the time that was nearly
free: `ChainTipFactsFfi` carries `reserved: [u8; 6]` (`ffi.rs:314-323`), so a
`nettype` byte could have landed in reserved space **with no layout movement
at all**. Then `VC-R2` added a 32-byte genesis hash to the same field list,
and 32 bytes do not fit in six. The estimate was never revised; §4's slice row
inherited it and expressed it as an ABI-churn warning, which is the same
un-revised number wearing a different face.

**`VC-R17` splits the seam instead of managing the churn.** The identity facts
go in their own POD: `ChainTipFactsFfi` does not move, so its layout twins,
its `_test_fill` / `_rust_fill` seeded indices and its offset pins do not move
either. The precedent is already in the header — `shekyl_rpc_fee_grace_blocks_max`,
`shekyl_rpc_peerlist_limits` and `shekyl_rpc_span_pruning_seed` (`ffi.rs:741`,
`:776`, `:779`) are narrow exports for facts with no business in a bigger POD.
`nettype` and the genesis hash are process-lifetime constants — fixed at
daemon start and per network — while the tip POD's contract is "what the chain
tip looks like right now"; five of its six callers want a tip and one wants
identity.

**`DaemonNetwork` is a wire-side type**, in `shekyl-rpc-types`, with four
variants including `Fakechain`, deserialised from the daemon's string with
unknown strings refused. It is **not** `shekyl_address::Network`, which
stays three-variant: adding `Fakechain` there is the workspace-wide change
(`V3_WALLET_DECISION_LOG.md` :1397 — HRP tables, `NetworkSafetyConstants`,
`DerivationNetwork`, region-1 byte) that Phase 1 deferred, and this round
does not reopen it. The comparison in §3.6.4 maps between the two.

**The oracle chain.** `rpc_parity.rs`'s
`the_get_version_chain_differs_by_exactly_the_version_at_every_link`
asserts each consecutive vector pair differs by the version and nothing
else. The `v4 → v5` link will differ by the version **and** the two new
fields, so `VC-2` extends the test to name, per link, the fields that link
may add — in the shape of RK-4c's
`v2_is_v1_minus_exactly_the_two_retired_members`, which did the same for
removals. The invariant stays "exactly the version, plus exactly the named
members"; it does not become "roughly the version".

**Rule 42:** `GetVersionResponse` is a wire type, not a persisted block;
`CORE_RPC_VERSION` is the wire's own version constant and is what moves. No
persisted-schema constant is touched.

### 3.6 `VC-D6` — per-arm mismatch policy

Each arm is a different consumer with a different consequence of proceeding.
Each gets its own justification; none gets a "continue anyway" mode (§1).

#### 3.6.1 Console, live arm (`Source::Live`) — no check, because it cannot fail

`shekyld`'s interactive console renders from the live core in the same
process (`console/mod.rs`, `Source::Live(Arc<CoreRpc>)`). Its compiled
version and digest are the daemon's compiled version and digest by identity
of the binary. A check here compares a value to itself, can never fail, and
would be a check that exists to be seen existing. **The parent's sketch
"local console fatal at startup" is rejected on that ground** — every check
must be able to fail.

#### 3.6.2 Console, remote arm (`Source::Remote`) — refuse to render, except `version`

`shekyld <command>` from a second process posts to an address that may be a
different binary. Before rendering any natively-served command, the console
calls `get_version` and compares every axis of §2 — **four since `VC-D12`;
this sentence said "all three" until `VC-R7` caught it** (§8). On mismatch it prints the
axis, both values and (for the wire axis) which side is older, and exits
non-zero without rendering the command. The one exemption is **`version`
itself**: its job is to show the operator what they are talking to, so it
renders both sides and the verdict rather than refusing — it *is* the
handshake, made visible.

Rejected: an override flag to render anyway. A console that renders
statistics from a chain it has just proved is not this build's chain prints
confidently wrong numbers, which is the failure §0.3 was written to avoid.
There is no operator task that needs it that `version` does not serve.

#### 3.6.3 Wallet engine — refuse to open, on every axis

`Engine::open_*` (`engine/lifecycle/open.rs`) performs the handshake against
the supplied daemon client **before any wallet operation** — lock 5's
wording, finally honoured — on all four axes of §2, **all four read from the
one `get_version` reply** (`VC-R2`), and refuses with a new typed
`OpenError::DaemonIdentityMismatch { axis, ours, theirs }`. `shekyl-cli` and
`shekyl-wallet-rpc` surface it in operator language per
[`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc):
what is wrong, which side, and the one action that fixes it (point at the
right daemon; update the older side). The existing
`OpenError::NetworkMismatch` keeps its meaning (wallet file vs caller) and
its name; the daemon axis is a different error because it is a different
fact.

**Refusing to read, not only to submit.** The parent's sketch offered
"wallet engine refuse to submit" and the dispatch suggested that refusing to
*read* "may be merely annoying". It is not, twice over:

- on the **rules** axis, reading is scanning a different chain — the balance
  and history shown are computed under rules this wallet does not implement,
  and a user who acts on them acts on a number that is not theirs;
- on the **wire** axis, reading is where the `#[serde(default)]` zero lives
  (§0.4): a read against a skewed daemon can succeed and be silently wrong,
  which is strictly worse than a submit that fails loudly.

Refusing at open closes both with one check and gives the operator the
message at the moment they can act on it.

**The residual, named (`VC-R4`, §8).** "There is no arm where proceeding is
better than stopping" (§1) is true of this engine *because it has no offline
open path* — every `open_*` takes a `DaemonClient` by value
(`lifecycle/open.rs:185`, `:339`, `:358`), so a wallet already cannot be
opened without a daemon and refusing at open takes nothing away that exists.
That is an accident of the current API, not a property of the axes: on the
**wire** axis a mismatch means the two binaries cannot converse reliably, not
that the chain differs, and a user whose node upgraded first is locked out of
their own wallet entirely — no cached history, no export — until one side
moves. The own-node default ([`docs/DAEMON_RPC_RUST.md`](../DAEMON_RPC_RUST.md))
bounds it:
both binaries normally ship together, so the skew is the operator's own
rebuild rather than a remote's choice. **Reopen** if an offline open path is
ever built: the wire axis should then refuse daemon *operations* while
letting the file open, and the uniformity claim must be re-derived rather
than inherited.

**When it runs.** At open, and whenever the engine constructs or replaces its
daemon client. **Rejected for this round:** a periodic re-handshake during a
long session, to catch a daemon swapped underneath a running wallet. Reopen
when the RT transport posture takes up session-long peer binding; the
handshake is one more fact that binding should carry, and building a poller
here first would be building it in the wrong layer.

#### 3.6.4 Regtest — a typed acceptance, never a string

**RULED (ruling 3, 2026-09-06, relayed): the typed `FakechainPolicy` with
default `Refuse`, and no equivalence ruling for an existing regtest lever.**
Rick's reason: this is the `SEEDHASH_EPOCH` shape and rule 71's compliant
counter-pattern — armed explicitly, refused by default, set only by the
harness or a named operator flag — and reusing an existing lever would make
the test affordance implicit again, *which is the exact defect that hid
CEN-B5 and cost the block-60 halt*.

A `shekyld --regtest` daemon reports `nettype: "fakechain"`
(`cryptonote_core.cpp:423` sets `FAKECHAIN`); the regtest end-to-end suite
opens `Network::Mainnet` wallets against it, because fakechain shares
mainnet's address format and the address enum has no fourth variant. A
strict network check refuses every e2e run on day one.

**Ruled (2026-09-07, `VC-R3` carried further than the finding went):** the
network axis passes when `wallet.network` maps to the daemon's
`DaemonNetwork`, **or** when the daemon reports `Fakechain` and the caller
passed `FakechainPolicy::Accept` — a typed parameter of the open path with a
default of `Refuse`, **set in-process by the regtest harness
(`regtest_e2e.rs`) and by tests, and by nothing else. There is no operator
flag, and none ships.** It is a type, not a string comparison and not an
environment variable: the fakechain schedule lever in
`lifecycle/assemble.rs:407` is an environment variable and is the precedent
this deliberately does *not* follow, because an env var is set once and
forgotten and a typed parameter is visible at every call site.

**Why no flag, in Rick's terms.** The harness constructs the client, so it
can arm the policy in-process with no operator-facing surface at all. A flag
that exists only for tests but ships in the production binary is exactly the
implicit affordance this document already credits with hiding `CEN-B5`, and
it is the kind of thing that reaches a support forum as "just add this
flag". **The asymmetry decides it:** no flag costs a rare operator workflow
some friction; the flag costs the only defence against a mainnet wallet
scanning a regtest chain a documented off-switch. Under privacy before
features that is not close. If an operator genuinely needs it, the answer is
a debug build or a config path that is not in the shipped artifact — never a
CLI argument on the binary people run against mainnet.

**Reopening criterion:** a *named* operator task that requires it, at which
point the surface is re-derived from that task rather than provisioned
ahead of it (rule 21).

Rule 71 is respected: the network selects **data** (the value compared), and
the fakechain arm is not a consensus-surface divergence — it is a test and
developer harness lever, named, typed, defaulted off, and loud in the CLI's
`--help`.

**`VC-R3` (§8) contests the operator-facing half of this**, not the typed
policy. A `fakechain` daemon takes mainnet's configuration
(`cryptonote_config.h:562`), so it shares mainnet's genesis hash *and* its
constants digest; the network axis is the only one that can tell the two
apart. A shipped `--allow-fakechain-daemon` is therefore a switch that
disables the sole axis separating a regtest chain from mainnet, and a
mainnet wallet run behind it scans a fake chain with real addresses — the
lock-5 failure this round exists to close, re-enabled by a flag. The harness
needs `Accept`; no operator task has been named that needs it. **Open, needs
Rick** (§8).

### 3.7 `VC-D7` — genesis behaviour: a claimed property, with the constraint it imposes

Pre-genesis the constants file moves and the digest moves with it; a client
built before the move refuses a daemon built after it, names the axis, and
the developer rebuilds. That is the intended behaviour and it is how the
mechanism gets exercised before it matters.

At genesis the files freeze and the same comparison becomes an assertion of
**digested-authority identity**: every client and daemon that agree were
built from the same `config/` integer authorities. **It is not "rules
identity", and `VC-R6` (§8) corrects that overclaim.** Consensus-affecting
values live outside those files today by the authority's own admission — its
`_comment_daa` records that the LWMA-1 bias `99/200`, the solvetime clamp and
the min-L floor "deliberately do NOT live here", as literals in `lwma1.rs` —
and `C2-R2` §8 is queued to migrate the weight and fee constants *in* from
`cryptonote_config.h`, which is only a migration because they are outside
today. A daemon built from identical JSON and a patched literal passes this
axis. **The claim the design may make is the one the digest can carry**;
rules identity becomes available only when the constants a rule depends on
are all inside the digested set, and that is a named precondition rather
than a property to assume. Together with the network axis
(§2), that is chain identity, and it is **claimed as a property** of this
design, not left as an accident. Any post-genesis edit to the file produces
a digest no genesis-built client accepts, which is correct: an edit to the
consensus constants *is* a new rule set, and the one planned rule change in
Shekyl's life — the V4 lattice-only transition — is by definition a new
chain state that every party must opt into. This mechanism refuses silent
participation in it, which is the autonomy property
([`75-system-autonomy`](../../.cursor/rules/75-system-autonomy.mdc)) applied
to a client.

**The constraint the claim imposes.** The file's membership rule — *only
consensus-affecting constants live here* — becomes binding, not advisory. One
stray tunable (a default timeout, a UI constant) placed in this file makes
every client refuse every daemon built after it moved, for a change to
nothing that matters. `VC-1` adds that sentence to the file's leading
`_comment`, and the reviewer of any JSON addition owns the question "does a
different value of this make a different chain?" If the answer is no, the
constant does not belong in the file.

### 3.8 `VC-D8` — the P2P handshake does not carry the digest in this round

Peers with different consensus constants are a different and more serious
problem than clients with different constants, and the digest is exactly the
fact a peer handshake would want beside the network ID. **Rejected for this
round.** The P2P handshake is a consensus-surface commitment owned by the
P2P-2 design round (the B7/B8 drop-semantics work), it is Levin wire rather
than RPC, and its mismatch policy (drop? ban? score?) is a peer-management
question this round has no standing to answer.

**Reopening criterion:** P2P-2 takes up peer identity beyond the network-ID
bytes. `CONSENSUS_CONSTANTS_DIGEST` is then a ready-made value with pinned
canonicalisation; this document is the reference for what it means and does
not mean (§1).

### 3.9 `VC-D9` — the Python generator emits no digest

Rejected with `VC-D4`: no C++ consumer exists. **Reopening criterion:** a C++
consumer of the digest appears — which, given the direction of the FFI
boundary ([`20-rust-vs-cpp-policy`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)),
should first be asked whether it ought to be Rust.

### 3.10 `VC-D10` — no intra-binary agreement check

One daemon binary is a C++ half (consensus, `consensus_constants_generated.h`
at CMake configure time) and a Rust half (`build.rs` at cargo build time),
both reading the same file in the same tree. Could they disagree, so that the
digest the Rust half publishes describes a file the C++ half did not read?
`CMAKE_CONFIGURE_DEPENDS` on the JSON and `cargo:rerun-if-changed` on the JSON
make both regenerate on every edit; the existing `static_assert` /
`const _: () = assert!` sentinels pin both halves to the same values at every
consuming site; and a divergence would be a build-system defect with a blast
radius far larger than this check. **Rejected.** **Reopening criterion:** the
two halves are ever built from different trees — for instance a prebuilt Rust
image linked into a C++ build — at which point the digest should be emitted
on both sides and compared at daemon start, and `VC-D9` reopens with it.

### 3.11 `VC-D11` — the narrow `T` check is deleted when the general one lands

`console/info.rs`'s `daa_target_seconds` warning (§0.3) is a subset of the
rules axis. Once `VC-3` refuses a remote console on a digest mismatch, the
warning's condition (`reported != authority` on a daemon whose digest
matched) can only arise if the same file produced two different `T`s, which
the sentinels make impossible. It becomes unreachable, and unreachable code
that looks like a check is the class rule 47 exists for. **`VC-3` deletes
it** and its tests, and re-points the doc comment that names this round.
Rule 15: pre-genesis, delete rather than keep two instruments for one fact.

### 3.12 `VC-D12` — the digest's file set: `consensus_constants.json` alone, or all of `config/`?

Raised by the steering lane on 2026-09-05 while correcting a relay: the
fee-ladder implementation bundle touches `config/economics_params.json`, not
`consensus_constants.json`, so it would **not** trip `VC-1`'s sentinel — and
that is the gap. `economics_params.json` is at least as consensus-affecting
as the file `VC-1` digests: `money_supply`, the emission speed and final
subsidy, the burn rates, the staker shares, `coin` (the atomic-unit
denominator), `shekyl_tx_volume_window` (the fee ladder's window). What
guards it today is `rust/shekyl-economics/src/digest.rs`: a Blake2b-256 over
the typed `EconomicParams`, used as the C4 fixture-lineage guard and as one
leg of `snapshot_calibration_digest`. That is a **different instrument with a
different job** — it detects drift between a committed fixture and the
params, it does not fail the build against a pinned value, and its module
doc deliberately keeps it `EconomicParams`-only so fixture lineage does not
move when an unrelated constant changes. Its narrowness is correct for its
job; the consequence is that **seven** of `economics_params.json`'s eighteen
non-comment keys (`coin`, `display_decimal_point`, `shekyl_fixed_point_scale`,
`shekyl_tx_volume_window`, `shekyl_staker_emission_share`,
`shekyl_staker_emission_decay`, `shekyl_blocks_per_year`) have no build-time
guard of any kind. The honest answer to "what guards `economics_params.json`
against a client/daemon mismatch" is currently *nothing*.

**RULED (ruling 5, 2026-09-06, relayed): widen to both integer authorities,
before this PR merges; canonical form `v2`, one re-pin — built.** The file
settled it: `economics_params.json` carries `money_supply`,
`final_subsidy_per_minute: 300000000` and
`emission_speed_factor_per_minute: 22` — genesis-frozen emission constants,
and the final subsidy *is* the perpetual tail Rick signed in `FL-R12′`
(0.3 SKL/min × 2 min/block = the 0.6/block rail). "A digest pinning
`consensus_constants.json` while leaving the emission curve's own authority
unguarded pins the smaller half."

Three things ride with the widening:

(i) **What the digest is — a change detector, not a freeze.** That file's
own `_comment_escalation` states the D2 escalation numbers are
provisional-until-testnet under a GF-7 freeze ceremony. The pin does not
prevent that change; it makes each ceremony's re-pin *visible*. Written
here, in the file's new `_comment_digest`, and in the sentinel's comment, so
the next reader does not take a green digest as evidence the values are
frozen and argue the ceremony against a gate that never claimed that.

(ii) **Sequencing — predicted wrongly, and corrected 2026-09-08.** This
said the rename lands in the fee lane's third PR and that "`VC-1` widens
first; the rename re-pins". **The rename landed first** (`dev` `aeb601552`,
`money_supply` → `emission_curve_asymptote`), so `VC-1`'s own merge re-pinned
`6e1f9125…` → `fab6f63e…`. The lesson is not about this rename: **a
sequencing note is a claim about merge order, which no lane controls**, so
it should be written as "whichever lands second re-pins" rather than as a
prediction. The re-pin question was answered on the merge (§7): the key moved
and the value did not, and the question is asked of the value the new name
binds — the asymptote is consensus, so the digest moving is correct.

(iii) **A discrepancy to grade, not necessarily to fix — two year
conventions.** Economics uses 365 days: `shekyl_blocks_per_year: 262800`,
derived explicitly in `DESIGN_CONCEPTS.md` as `(60/2) × 24 × 365`, eight
code sites. `FA-6_VIEW_TAG_ML_KEM.md` :695 derives its key-rotation horizon
on 365.25: `N_blocks = ⌊(5 × 365.25 × 86400) / T_block⌋ = 1,314,900`, which
is 262,980 blocks/year *implied* — that literal appears nowhere in the tree.
(The other 365.25 sites, `console/mod.rs:837` and `util.cpp:1096`, format
human-readable durations and are out of scope.) The gap is 180 blocks a
year, 900 over FA-6's five-year window. The question is not which constant
wins but whether a rotation horizon derived on a different year length than
the emission schedule matters across five years. **This document's grade:
the 365-day economics convention is authoritative for anything that touches
emission, fees or staking arithmetic, because it is the value in the
digested authority; FA-6's horizon is a security margin, where 900 blocks of
slack in 1.3 million is noise, and it may keep 365.25 provided it says so
beside the derivation.** One line in FA-6 naming the convention closes it;
that line is FA-6's, not this round's.

The disposition as proposed, kept because the ruling adopted it:

**The rules digest covers both integer authorities under `config/`
— `consensus_constants.json` and `economics_params.json` — as one digest,
one wire field.** The canonical form (§3.3) gains a per-file section: after
the header line, for each file in a fixed order, one line naming the file
(`= config/consensus_constants.json`) followed by its sorted `key value`
lines. Both files are already integer-only (18 of 18 in
`economics_params.json`), so rules 2–5 apply unchanged; the header bumps to
`…-canonical-v2` because the form changed. Two digests (one per file) were
considered and rejected: two wire fields for one question — "same rules?" —
and a second thing a client can forget to compare. Rule 19 says bundle by
validation surface, and the surface is "the constants this binary was built
from".

**A rename is cheap now and a compatibility break later — named while it is
still free to write down.** The rule below (a key is part of the binding)
was argued; its cost is now *observed*, because the pin fired on the first
merge after `VC-1` was built, on a refactor with no consensus content at all
(`FL-R15`, §7). Pre-genesis that costs a re-pin. **Once `VC-2`…`VC-4` land, a
rename in either authority file makes every older client refuse every newer
daemon while the chain is identical** — the digest cannot tell a rename from
a rule change, and by `VC-D15` it will not guess. So **post-genesis a rename
in these files is a client-compatibility break that rides a release
boundary, not a cleanup PR**, and the release note owes it a line. **Reopen**
the value-only view only if renames in these files ever become frequent
enough that the compatibility cost outweighs a rename's ability to silently
repoint a consumer — which is the reason the value-only view was rejected,
and which does not weaken with time.

**A key rename moves the digest, and should.** The fee-ladder bundle's
`FL-R15` renames `money_supply` → `emission_curve_asymptote` with the value
unchanged. Under the canonical form the digest moves, because the key is
part of the binding: a constant is a *name* bound to a value, every
generator reads it by name, and a build where the name moved is a build
whose generators were rewritten. The re-pin question ("does a different
value of what moved make a different chain?") is answered for a rename by
asking it of the value the new name binds — the fee-ladder lane's own answer
for the asymptote is yes. The design does not add a value-only view to
excuse renames; a rename that is not worth a re-pin is a rename that should
not be made to this file.

### What the digest covers, what it does not, and what the remainder costs (`VC-R11`)

The word **"integer"** in "both integer authorities" was doing load-bearing
work as an adjective. Written as a boundary instead:

| | Surface | Status |
| --- | --- | --- |
| **Covered** | every non-`_` key of `config/consensus_constants.json` and `config/economics_params.json` — 22 + 18 keys at `VC-1` | digested; any edit moves the digest |
| **Not silently excluded** | a non-integer value under a non-`_` key in either file | **fails the build**, naming file and key (§3.3 rule 5) — the adjective is a **tripwire, not a filter**: today it excludes nothing, because every value in both files is an integer, and the day one is not, the build stops rather than the digest quietly shrinking |
| **Excluded, covered elsewhere** | `config/genesis_recipients.{mainnet,stagenet,testnet}.json` | per-network and non-integer; what they determine is the genesis block, checked directly by the tuple's fourth axis — **conditionally; see the trigger below** |
| **Not covered** | consensus-affecting values outside `config/` — the LWMA-1 bias `99/200`, the solvetime clamp and the min-L floor as literals in `lwma1.rs` (by the authority's own `_comment_daa`); the weight and fee constants in `cryptonote_config.h` that `C2-R2` §8 is queued to migrate in | **outside the digest, and the claim is scoped accordingly** |

**What the remainder costs, stated rather than waved at.** The uncovered set
is not safe; it is *unclaimed*. A daemon built from identical JSON and one
patched literal in `lwma1.rs` passes the rules axis while running different
rules. That is why `VC-R6` downgraded §3.7's claim from rules identity to
digested-authority identity: the mechanism attests what it digests and the
document may claim no more. `C2-R2` §8's migration narrows the gap by moving
constants *into* the covered set, and full rules identity becomes available
only when every constant a rule depends on is inside it — a precondition
with a named owner, not an assumption.

**The per-key membership grade (`VC-R19`), because "integer authority" was
doing the work of a decision one level up.** `VC-R11` closed that move for the
*type* of values; the same move survived at the choice of *keys*, which were
ingested wholesale. All eighteen economics keys were walked. The grade is
recorded so §3.7 is checkable by a reviewer rather than aspirational:

| Key(s) | Does a different value make a different chain? |
| --- | --- |
| `emission_curve_asymptote`, `emission_speed_factor_per_minute`, `final_subsidy_per_minute` | **Yes** — the emission curve and the perpetual tail (`FL-R12′`) |
| `coin` | **Yes** — the atomic-unit denominator |
| `display_decimal_point` | **Yes, but only through a coupling that was nowhere written down** — see below |
| `shekyl_fixed_point_scale` | **Yes** — the denominator every ppm share is read against |
| `shekyl_staker_pool_share`, `shekyl_staker_emission_share`, `shekyl_staker_emission_decay`, `shekyl_blocks_per_year` | **Yes** — the staker split and its decay (`calc_effective_emission_share`) |
| `shekyl_burn_base_rate`, `shekyl_burn_cap`, `shekyl_tx_volume_baseline`, `shekyl_tx_volume_window` | **Yes** — burn rate and the window it is measured over |
| `shekyl_escalation_asymptote_share`, `shekyl_escalation_knee_n`, `shekyl_release_min`, `shekyl_release_max` | **Yes** — D2 escalation; provisional-until-testnet, and §3.12 already rules that a change detector is *supposed* to move on them |

**`display_decimal_point` is the one that needed the walk.** On its own it is
a rendering convention, and a rendering convention does not make a different
chain — the finding was right to single it out. But "on its own" is a state it
cannot occupy: `shekyl-units/build.rs` asserts `coin == 10^display_decimal_point`,
mirrored by a `const _`, so the two move together or the build fails. The pair
moving together *is* a change to the atomic-unit denominator, which is
unambiguously a different chain. **It belongs — via the coupling, not via its
own semantics** — and that distinction existed nowhere before this grade.

So the finding is right as process and empty as outcome, which is the best
case a grade can have and still worth the edit: the next key added to this
file gets asked the question, and the answer for the one key that needed an
argument is now written down instead of re-derived.

### `genesis_recipients.*` are excluded, and the exclusion has a trigger (`VC-R12`)

**`genesis_recipients.{mainnet,stagenet,testnet}.json` are excluded from
the digest, and the genesis block hash becomes the tuple's fourth axis
(§2).** The files are per-network (which would break the
digest-is-orthogonal-to-network property §2 relies on) and non-integer
(strings and lists), so they do not fit the form; and what they determine —
the genesis block — is better checked directly, by comparing a per-network
pinned genesis hash against `get_version.genesis_hash` (`VC-R2` moved this
off `on_get_block_hash([0])`, so it is one field of the atomic reply rather
than a second call). **This document's first draft excluded them
on the claim that the genesis hash "already commits to them" and left the
comparison as a reopening criterion; the steering lane checked and the
criterion was already true — nothing pins a genesis hash in Rust and nothing
compares one.** An exclusion cannot rest on a check nobody performs, so the
check moves into scope: `VC-4` adds the Rust pins (per network, rule 71:
`nettype` selects the constant, never the control flow; derived from the
daemon's `GENESIS_TX`/`GENESIS_NONCE` and KAT-checked against a live daemon's
block 0 the way the txid KATs are) and the comparison, and refuses on
mismatch with the same shape as the other axes. Regtest: `FAKECHAIN` uses
mainnet's configuration, so a regtest daemon reports mainnet's genesis hash
and the axis passes for a `Mainnet` wallet under `FakechainPolicy::Accept`
exactly as the network axis does. **The exclusion depends on a ruling that has not landed, and that dependency
is named rather than assumed (`VC-R12`).** These files are out because the
genesis axis covers what they determine. If the genesis field does not ship,
the exclusion loses its cover and nothing in the tree would say so.

**The trigger.** The exclusion is conditional on `get_version.genesis_hash`
shipping **in the same change as the digest's first consumer**. Ruling 2's
fold makes that automatic — `VC-2`, `VC-3` and `VC-4` are one PR, so the
axis and the comparison arrive together or neither does. **If that fold is
ever split, this trigger fires:** the `genesis_recipients.*` files must
either join the digest, or the gap must be recorded as accepted with its own
reopening criterion.

**Why the window before then is not a gap.** `VC-1` ships the digest with
**no consumer** (§4), so between `VC-1` and the folded PR nothing compares
anything, and an exclusion with no cover has no consequence. Cover and first
consumer arrive on the same commit. That argument holds only while `VC-1`
stays consumer-less — which is itself observable, because a consumer
appearing early would be either a `get_version` field with no reader or a
reader with no field, and both are this round's founding finding recreated.

**Reopen** the digest question for these files if the genesis-hash axis is
ruled out entirely.

**The named first consumer.** The C2-R2 weight/fee round does not touch
`consensus_constants.json` today, but its §8 names migrating the weight and
fee constants *into* it as a store-port obligation — they are hand-maintained
in `src/cryptonote_config.h` with a `shekyl-wire` mirror. The port PR that
executes §8 is the first change that will meet the sentinel, and that lane's
own read of the re-pin question is **yes for every one of them**: the
penalty-free zone, the clamps and the surge factor are consensus; the
relay-policy trio is admission-visible. That is the mechanism doing what it
is for — a key addition forced through the question rather than past it —
and it is recorded here so the first red is met as the design, not as a
surprise.

**Cost, paid:** `VC-1`'s canonicaliser reads two files (`CANONICAL_FILES`,
one array, the build script and the tests both walk it), the KAT is a
two-file case with its expected digest recomputed by the independent Python
implementation, the sentinel was re-pinned once, `economics_params.json`
gained a `_comment_digest` carrying the membership rule and (i), and
`shekyl-economics`'s digest keeps its job untouched — two digests with
different jobs is right; a gap between them was not. The C++ economics
header generator's output is byte-identical before and after the comment
(verified, not assumed). Three new tests: file identity and order are part
of the form; an edit in *either* file moves the digest; a key rename with
the value unchanged moves it.

### 3.13 `VC-D13` — the property claimed is **connect-time**, and saying so is the point

`VC-R2` made the tuple atomic. Atomicity buys a true statement about **one
instant** and says nothing about the interval that matters: a client that
validates four axes in one reply and then issues a thousand requests has no
guarantee that request 900 was answered by the daemon that answered the
handshake. The same middlebox that could have straddled two handshake calls
can pass the handshake from node A and route the session to node B.

**Ruled: this design claims connect-time identity only.** The tuple is
established once, on the connection the client then uses, and the design
asserts nothing about later requests on it. Stated plainly because the
alternative is worse than silence: ruling 1's atomicity language implies a
property strictly stronger than one call delivers, and `VC-R2` closing the
two-call hole makes the remaining session-length hole *harder* to notice,
not easier.

**What an operator is expected to do about the gap.** On the default
posture — a wallet against its own node over a loopback socket — there is no
middlebox and the gap is theoretical: the process at the other end of a
local socket does not change identity mid-session without the socket
breaking. On a remote `--daemon-address` the gap is real, and the honest
statement is that this mechanism does not close it; the transport posture's
peer binding is where it closes.

**Rejected for this round, with criteria.** *Connection pinning* — validate
on the connection you then keep, and refuse pooled reconnects — is the
mechanism that would make the claim session-long, and it belongs to the
transport layer that owns connections, not to a handshake that borrows one.
*Cheap revalidation carried on every request* is the other shape and costs a
field on every reply. **Reopen either** when the remote arm carries value:
concretely, when a wallet holding funds is expected to run against a daemon
the operator does not control. Until then the tuple is a connect-time check
and the document says so.

### 3.14 `VC-D14` — every field of the identity tuple deserializes strictly

`get_version` is definitionally **pre-validation**: it is the call a client
makes *before* it trusts anything, so on the remote arm all four axes are
attacker-controlled bytes. Comparison is safe; **parsing is where the risk
lives**, and this crate already carries the hazard in two shapes:

- `#[serde(default)]` — **three figures, each scoped, because a bare count
  here is the defect this document keeps finding.** Field-level attribute
  sites, on this tree: **3** on `GetVersionResponse` itself
  (`chain.rs:351`, `:355`, `:359`), **11** in `chain.rs`, **44** across the
  crate's reply modules (`transactions.rs` 15, `chain.rs` 11, `headers.rs`
  10, `p2p.rs` 8). No struct-level `#[serde(default)]` exists, so every one
  is a single field. The open FOLLOWUPS item's "27 fields across those two
  modules" is a different **unit** — fields the audit judged defaultable,
  not attributes — and the two figures are not comparable without saying so.
  The module's own doc at `:30` states the consequence: "**This is not a fix
  for silent defaults.** `#[serde(default)]` still lets an *omitted* field
  become its zero value." An omitted axis compared against a zero value is a
  mismatch reported as agreement.

  **Which figure governs which claim:** the 3 are why `VC-D14` is a
  per-field rule rather than a struct-wide sweep; the 44 are why the hazard
  is called a property of this crate rather than of one struct.
- `#[serde(other)]` — `lib.rs:217`, documented at `:38` as fail-safe for
  `RejectCause`, where an unknown cause collapsing to `Unrecognized` is the
  *safe* direction. On `nettype` the same attribute would be the unsafe
  direction: an unknown network would parse to a catch-all instead of
  refusing.

Both turn "these disagree" into "these agree", which is the single failure
mode this whole design exists to prevent.

**Ruled:** the three new fields carry **no `default`, no catch-all, and no
`Option`**; an unrecognised `nettype` string is a deserialization error.
`DaemonNetwork` derives no `Default`, so `#[serde(default)]` on it would not
compile — that axis is structurally safe rather than safe by review. The
digest and the genesis hash can default and therefore need the rule.

**The rule is pinned by tests, not by this paragraph:** for each of the
three fields, a reply with that field **omitted** must fail to deserialize,
and an unknown `nettype` string must fail. A requirement that only a comment
asserts is the class this round keeps finding.

**Compatible with the struct as it stands.** `GetVersionResponse` already
carries `#[serde(default)]` on `current_height`, `target_height` and
`hard_forks` (`chain.rs:351`, `:355`, `:359`), because the C++ side omits
them via `KV_SERIALIZE_OPT` and the oracle vectors depend on that. Those are
not tuple fields. The requirement is per-field on the identity tuple, not a
sweep of the struct — the wider `#[serde(default)]` audit remains its own
FOLLOWUPS pass.

### 3.15 `VC-D15` — a refusal names the stale side only where a side *is* older

The operator-facing goal is "one of these is out of date, say so". Three
axes support it. **The digest does not:** it is a hash, so a mismatch proves
disagreement and carries no ordering. Nothing in a digest comparison can
tell an operator to update the daemon rather than the wallet.

**Ruled, and it is not "pick an ordering mechanism".**

1. **When the wire version differs, it names the side.** `CORE_RPC_VERSION`
   is ordinal and monotonic, so the refusal says which build is older and
   which to update. This is free and covers the common case, in which a
   rebuild moved both the wire and the constants together.
2. **When *only* the digest differs, the refusal refuses to guess.** It says
   what the fact means instead: the two builds share an RPC contract, so
   neither is a stale release — one tree's `config/` was edited relative to
   the other, which is a different rule set rather than a version skew. It
   names the digested files and both digests. That is more actionable than a
   fabricated ordinal, and it is the *motivating* case of this entire round
   (§0.4's middle row: a daemon rebuilt from edited constants with an
   unchanged wire shape), so covering it with a guess would be worst at
   exactly the point the design exists for.

**Rejected: a monotonic constants-generation counter beside the digest**
(the other option offered). It is hand-maintained, so it can be forgotten,
and a forgotten counter makes two different rule sets claim the same
generation. That failure is survivable only because the digest — not the
counter — remains the authority for *equality*, which means the counter buys
ordering in exactly the case where its own reliability is unverifiable.
**Reopen** if constants ever change on a published schedule post-genesis,
where an ordering with a named owner would have a real consumer.

---

## 4. Implementation slices — named, not started

`VC-1` is built and widened (this PR). **`VC-2`…`VC-4` are authorised for
alpha.8 as one folded PR (ruling 2); the PR body's first paragraph states the
four axes.** They are not started. Each slice runs the CI-exact gates
(`cargo fmt --all -- --check`; `cargo +1.94.0 clippy --workspace
--all-targets --keep-going -- -D warnings`; `cargo test --locked --workspace
--exclude shekyl-randomx-differential`) on the tree it pushes, plus what each
row names, plus **the doc gates enumerated from `scripts/ci/check_*.py` at
that moment rather than from a remembered list** — a remembered nine against
17 in the tree is what `VC-R14` caught, and a gate set is a moving
denominator. The citation ratchet needs `git submodule update --init
--force --recursive` first or it refuses, which is a broken run and not a
pass.

| Slice | Contents | Wire change? | Additional gate |
| --- | --- | --- | --- |
| **`VC-1`** — **BUILT** in this document's PR (`dev` e54e5b983) | `shekyl-rpc-types/build.rs` + `CONSENSUS_CONSTANTS_DIGEST` and `CONSENSUS_CONSTANTS_CANONICAL` (§3.3, §3.4), with the canonicaliser in `build_support/consensus_canonical.rs` included by both the build script and the tests — one definition; canonical-form KAT whose expected digest was computed by an independent Python implementation of §3.3; live-file pin (`PINNED_DIGEST` in `build.rs`, with a case-branching panic — `VC-R5`, `VC-R13`); `DaemonNetwork` type with string round-trip and unknown-string refusal tests; the membership-rule sentence in the JSON's `_comment` (§3.7). | **No.** Nothing on the wire moves; the constant exists and is tested; nothing reads it yet, and `consensus_digest.rs`'s module doc says so. | Red observed before trusting green, two ways: with the sentinel disabled, a descending key sort fails `kat_pins_the_canonical_form_and_its_digest` and `the_live_canonical_form_has_the_shape_the_design_pins` while `the_build_used_these_rules_on_the_live_file` stays green (build script and tests share the mutated rules — the Python-derived KAT is what catches a drift both sides share); with the sentinel enabled, the same mutation fails **compilation** on the pinned digest, which is the sentinel doing its job first. |
| **`VC-2`** — **AUTHORISED for alpha.8, fold with `VC-3`/`VC-4`** (ruling 2: "a wire change belongs in the paired release, not first-thing-after where it becomes the first uncovered delta of the next cycle") | `GetVersionResponse` + **3** fields (digest, `nettype`, `genesis_hash` — `VC-R2`), each strictly deserialized with an omission test (`VC-D14`); `CORE_RPC_VERSION` → next minor, **read from `dev` at write time**; `get_version_synced_v5.json` and siblings for the other two `v1` states; chain-delta test extended per §3.5; a **separate identity POD** carrying `nettype` and the genesis-hash bytes — **not** a widening of the chain-tip POD (`VC-R17`) — plus its C export and ABI offset pins. **This is an ABI addition with layout twins and a round-trip pin:** `_test_fill` / `_rust_fill` and the seeded field indices apply to the new POD, and its offset pins are re-derived rather than edited. It is the part of `VC-2` that breaks quietly if done by hand; `methods.rs` fills both fields. **Pre-flight pass first (rule 26).** | **Yes.** Needs Rick's ruling on alpha.8 timing (§6). | `rpc_parity` whole chain green; the four-spelling version pin updated; C++ `ninja -C build` + unit suite (the POD changed). |
| **`VC-3`** | Console remote arm handshake (§3.6.2); `version` exemption; delete `daa_target_seconds` and its tests (§3.11); operator-facing message tests for all three axes and both "older side" directions. | No (consumes `VC-2`). | A test per axis that observes the refusal on a fabricated mismatched reply, and one that observes `version` rendering both sides. |
| **`VC-4`** | Engine open-time handshake (§3.6.3) on all four axes, including the per-network genesis-hash pins compared against `get_version.genesis_hash` (`VC-D12`, `VC-R2` — one reply, not a second call); the connect-time-only claim stated in operator terms (`VC-D13`); refusal wording per `VC-D15`; `OpenError::DaemonIdentityMismatch`; `FakechainPolicy` (§3.6.4) threaded through `open_*`, set by `regtest_e2e.rs` and the operator flag; **fix the two false docstrings** (`daemon.rs:169`, `error/mod.rs:41`) to say what the code now does, **and amend `WALLET_REWRITE_PLAN.md` :216 itself** (`VC-R20`): cross-cutting lock 5 still names `get_info` as the carrier, and a reader of the lock will otherwise try to put the check back on a bridged leg that `RK-5c` retires. The lock's *requirement* is unchanged and finally honoured; only its named carrier moves to `get_version`. **The two states are not equally bad and the worse one is the later one:** today the lock and the mechanism disagree because the mechanism is *absent*, which reads as work owed; after `VC-4` they would disagree because the mechanism is *present* and the lock describes a different one, which reads as a discrepancy to reconcile — and a reader reconciling toward a Phase-1 lock implements it as written, onto the bridged leg `RK-5c` retires, over two round trips, which is the exact shape ruling 1 rejected; `shekyl-cli` / `shekyl-wallet-rpc` messages per rule 82. | No (consumes `VC-2`). | Regtest e2e green with the policy passed; a lifecycle test per axis observing `open_full` refuse; a test that `FakechainPolicy::Refuse` (the default) refuses a `fakechain` daemon. |

`VC-1` landed with this document: the steering lane ruled (2026-09-05) that
code with no wire change and no C++ clears the throttle, and the enabler
ships with its own oracle (the KAT and the sentinel) rather than waiting for
a consumer that cannot exist until `VC-2` is authorised. `VC-3` and `VC-4` land in **one PR** with `VC-2` (ruling 2 — fold, do not
split): producers and callers in one PR is the standing rule, and a
`get_version` field with no consumer would be the very finding this round
opened with, recreated.

### 3.16 `VC-D16` — when `get_version`'s own shape is what changed

The tuple is compared after the reply parses. Every tuple field is strict
(`VC-D14`) and the reply type carries `deny_unknown_fields`, so a daemon
whose `get_version` shape has moved does not produce a mismatch on any axis —
it produces a **deserialization error**, before any axis is read. This is the
handshake's bootstrap case and it is not an edge: a wire-version skew *is*
what it looks like on the first method a client calls (`VC-R22`).

**Ruled: a `get_version` that does not parse is a wire-axis failure, reported
as one.** The shape of the handshake reply is part of the RPC contract, so a
reply that does not fit this build's type is the wire axis disagreeing —
reached by a different route than a version number comparison, and meaning
the same thing. The refusal says so in those terms: *this daemon's
`get_version` does not match the contract this build was compiled against, so
the two are on different RPC versions*, naming the field that failed as
evidence rather than as the headline. It must not surface a bare serde error
naming a field, which tells an operator nothing about what to do
(`82-failure-mode-ux.mdc`), and it must not be retried.

**The version number is unavailable in this case, and the design does not
pretend otherwise.** A reply that will not parse cannot be mined for its
`version` to name the older side, and `VC-D15`'s ordering therefore does not
apply here. **Rejected: a lenient pre-parse** that extracts `version` from an
otherwise-unparseable reply to improve the message. It would put a second,
weaker parser on the exact surface `VC-D14` just made strict — the first code
to touch untrusted input — to buy a nicer sentence. The operator's action is
identical either way: align the two builds. Say that, rather than parsing
loosely to say which.

**Reopening criterion:** a post-genesis compatibility window (`VC-D1`'s
reopen) would need a stable minimal envelope that older and newer builds can
always parse. That is a wire-design question for the round that opens the
window, and it is the natural place to reconsider a two-stage parse — under a
contract that guarantees a floor, rather than as a rescue attempt on a reply
that already failed.

### `VC-2`'s pre-flight, pre-registered (rule 26)

Rule 26 puts a pre-flight pass between design closure and production code.
`VC-2`'s scope is registered here, before it starts, because both items below
are ones a clean local run does not catch.

**1. The version constant is read, not carried.** `VC-2`'s first act on its
own tree is reading `CORE_RPC_VERSION_MINOR` from `dev` — not taking a number
from this document, a commit message, or a conversation. `chain.rs:59-70`
records what happened the last time two branches each wrote that line
honestly and git merged them character-for-character, and the whole-chain
delta test catches a taken number only **at merge**, which is late. The
protective sequencing is therefore: merge this PR, cut `VC-2` from the merge
commit, read the constant as the first act on that tree. It was 28 on `dev`
at `38dfb8485`, and that sentence has a shelf life measured in hours, which
is the reason it is written as a procedure rather than as a value.

**2. The POD widening is the part where a green local suite proves little.**
The chain-facts POD gains `nettype` and the genesis-hash bytes. It has layout
twins and a round-trip pin, so `_test_fill` / `_rust_fill` and the seeded
field indices move with it, and the **offset pins are re-derived, never
edited** — an edited pin agrees with whatever the code now does, which is the
one thing a pin must not do.

**The evidence that counts is cross-language, and the reason is worth
stating.** The failure mode is an ABI disagreement between two halves that
were **both built from the same tree**, so a Rust-only test and a C++-only
test can each pass while the boundary is wrong: each half is self-consistent
with its own idea of the layout. What discriminates is a value written by one
half and read by the other through the real export, plus offsets re-derived
from both sides and compared. `VC-2`'s pre-flight runs that before its
handler code, and records the result in this section rather than in a commit
message.

---

## 5. Rejected alternatives, in one place

| Rejected | In | Reopens when |
| --- | --- | --- |
| Version compatibility window | `VC-D1` | post-genesis window wanted; must co-rule `deny_unknown_fields` and close the `#[serde(default)]` item |
| Per-constant comparison list | `VC-D2` | never as such — a list is what the digest replaces |
| Raw-bytes file hash | `VC-D2` | never — the canonical form is cheaper than the false alarms |
| Per-consumer `build.rs` copies / shared build-dep crate | `VC-D4` | a consumer that cannot depend on `shekyl-rpc-types` appears |
| Two-method handshake (`get_version` + `get_info.nettype`) | `VC-D5` | RK-5c lands a typed native `get_info` **and** the FFI byte proves costlier than the duplicated field |
| Local-console startup check | `VC-D6` | never — it cannot fail |
| Console "render anyway" override | `VC-D6` | an operator task `version` cannot serve is named |
| Wallet refuses submit only, reads allowed | `VC-D6` | never — §3.6.3 |
| Periodic in-session re-handshake | `VC-D6` | RT session-long peer binding |
| `Fakechain` in `shekyl_address::Network` | `VC-D6` | unchanged from `V3_WALLET_DECISION_LOG.md` :1397 |
| Digest in the P2P handshake | `VC-D8` | P2P-2 peer identity beyond the network ID |
| Python generator emits the digest | `VC-D9` | a C++ consumer, after asking whether it should be Rust |
| Intra-binary C++/Rust digest compare | `VC-D10` | the two halves built from different trees |
| Keep the `T` warning beside the digest | `VC-D11` | never — unreachable once `VC-3` lands |
| Two digests, one per config file | `VC-D12` | never as such — one question, one field |
| Value-only view that ignores key renames | `VC-D12` | never — a key is part of the binding |
| `genesis_recipients.*.json` in the digest | `VC-D12` | no client-side genesis-hash comparison exists when `VC-4` lands |

---

## 6. Rulings — all four SIGNED in-channel 2026-09-07 (first relayed 2026-09-06; §7)

1. **The tuple and its carrier** (`VC-D2`, `VC-D5`) — **SIGNED as
   proposed**, on atomicity: one call, one snapshot, no skew (§3.5).
   Rick's ground: **typed atomicity beats documented discipline**, which is
   why this reason is better than the coupling argument it replaced. Two
   gaps named with the signature: `VC-R2`'s second-call contradiction
   (applied, §3.5) and the **scope** of the claim — one atomic call is a
   true statement about one instant, not about the session that follows, so
   the ruling's language implies a property stronger than one call delivers
   and needs its boundary stated (`VC-D13`, §3.13). The one-byte FFI
   widening is recorded as a **consequence, not an objection**: it is an ABI
   change to a struct with layout twins and a round-trip pin, so
   `_test_fill` / `_rust_fill` and the seeded field indices move with it
   (§4, `VC-2`).
2. **Alpha.8 timing of `VC-2`** — **SIGNED: lands in alpha.8, fold, do not
   split. The wire change is one of the major parts the release is waiting
   for.** The fold has a reason independent of schedule, and the round
   supplied it: `VC-R1` watched the version constant go stale in eight days,
   so three separate wire changes mean three bumps and three chances to
   collide, while one means one. `VC-3` and `VC-4` fold in, including the fourth axis. The PR
   body's first paragraph states the four axes.
3. **The fakechain shape** (`VC-D6`, §3.6.4) — **SIGNED on all three
   parts: typed `FakechainPolicy`, default `Refuse`, no equivalence ruling**
   for an existing lever. Default-refuse is fail-closed on an identity
   check, which is the only defensible default; typed-over-boolean is the
   same move as `TransportTls` replacing a `bool` earlier in this arc, which
   makes the fifth silent arm **unrepresentable rather than avoided**; and
   refusing to let an unrelated regtest lever imply acceptance keeps the
   implicit affordance that hid `CEN-B5` from reappearing. `VC-R3` then
   narrowed the ruling by deleting an affordance its own reason does not
   require, which is not contesting it.
4. ~~Whether `VC-1` lands now~~ — **ruled by the steering lane 2026-09-05:
   yes** (no wire change, no C++). Built in this PR.
5. **The digest's file set** (`VC-D12`) — **SIGNED: both integer
   authorities, widened before this PR merges** (§3.12), with the three
   carries (change detector not freeze; the **`FL-R15`** rename and `VC-1`
   ordering — **written at signature as "`VC-1` widens first and the `FL-R12′`
   rename re-pins", wrong twice: the rename is `FL-R15`, which implements the
   `FL-R12′` ruling, and it landed *first*, so `VC-1`'s own merge re-pinned.
   The durable form is "whichever lands second re-pins", because a sequencing
   note is a claim about merge order and no lane controls that (§3.12 (ii),
   §7)**; the two-year-convention grade). A digest over
   one authority while another goes undigested is the
   excluded-versus-forgotten hole with no signal. **Two denominator
   questions came with the signature** and are answered in §3.12: the word
   "integer" is load-bearing and must be a stated boundary rather than an
   adjective (`VC-R11`), and the `genesis_recipients.*` exclusion rests on a
   ruling that has not landed and needs a named trigger (`VC-R12`).

The banner moves to round 2. **Review round 1 (§8) found two of these
rulings load-bearing in ways their reasons did not cover** — `VC-R2` against
ruling 1's atomicity ground, `VC-R3` against ruling 3's operator flag — and
**both were upheld on 2026-09-07**, the second carried further than the
finding went (no flag at all, not a flag defaulted off). Round 2 (§9) then
added `VC-D13`…`VC-D15`. What remains open is implementation
(`VC-2`…`VC-4`); the §3.12 (iii) grade that belonged to FA-6 is written.

---

## 7. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-08 | **The pin fired for real, on another lane's change, and the prediction about the order was wrong.** §3.12 (ii) said "`VC-1` widens first; the `FL-R12′` rename re-pins". The rename landed on `dev` first (`aeb601552`, `money_supply` → `emission_curve_asymptote`, `FL-R15`) while this branch sat unmerged, so **`VC-1`'s own merge is what re-pinned**, `6e1f9125…` → `fab6f63e…`. The sequencing note was a claim about which PR would merge first, which is not a fact anyone controls; corrected here and in `FEE_LADDER_DERIVATION.md`'s `FL-R15` row. **The re-pin question was answered rather than skipped:** the key moved and the value did not, and `VC-D12` says to ask the question of the value the new name binds — the asymptote is the emission curve's asymptote, consensus, so the digest moving is correct. **`VC-R5` paid for itself on first contact:** the build printed the computed digest, so the re-pin was a copy rather than a hunt; under the shipped const-assert form the crate would not have compiled and the value would have been unavailable. **And the two digests over that one file disagreed, both correctly** — `shekyl-economics`'s parameter digest hashes values at fixed byte offsets and is name-blind, so its tests passed unre-pinned; `CONSENSUS_CONSTANTS_DIGEST` canonicalises `key value` pairs and is name-sensitive, so it moved. A key is part of the binding for an identity check, because every generator reads it by name, and is not part of it for a fixture-lineage check. Two instruments, two jobs, one file, and the earlier ruling that "two digests with different jobs is right; a gap between them is not" is what makes both answers correct rather than one of them a bug. |
| 2026-09-07 | **The four rulings are SIGNED in-channel; the relay caveat is discharged, and the sequence is kept because the discipline is what produced it.** They were recorded RULED on 2026-09-06 from a relay quoting Rick, with the provenance written into the banner as a relay rather than a signature and the consequence stated: if those were not his words, §6 was not closed and `VC-1` rested on nothing. They were his words, and the signature adds grounds the relay did not carry — **typed atomicity beats documented discipline** for ruling 1; the fold has a schedule-independent reason the round itself supplied, since `VC-R1` watched the version constant go stale in eight days, so three wire changes mean three bumps and three chances to collide; and typed-over-boolean on `FakechainPolicy` is the same move as `TransportTls` replacing a `bool`, making the fifth silent arm **unrepresentable rather than avoided**. **The caveat cost nothing and bought the correction sequence:** because the provenance was recorded rather than assumed, the round ran against dispositions marked unconfirmed, which is what left `VC-R2` and `VC-R3` free to contest two of them — and both were upheld, one carried further than the finding went. Had the relay been recorded as a signature, the same findings would have read as contesting settled rulings rather than as testing unconfirmed ones. |
| 2026-09-07 | **A fourth shape for the arc: a failure that suppresses its own explanation.** `VC-R5` found the live-file pin shipped as a const-eval assert that named the failure and could not name the computed digest — and, by failing, made the crate uncompilable, so the test that *would* have printed both values could not run either. The diagnostic was blocked by the very firing that made it necessary. The arc's catalogue now reads: **a gate that decayed** (RK-5b's already-closed-gap gate), **a condition never satisfiable** (the safety condition unsatisfiable at the moment it was written), **a correct mechanism no one reads** (`CORE_RPC_VERSION`, this round's founding finding), and now **a check whose remedy its own failure withholds.** The class is distinct because the earlier three are all caught by asking whether the check *can fire*; this one fires correctly and still leaves the developer stuck, so the catching question is different — *when this fires, is what it demands mechanically available?* Fixed by moving the pin into `build.rs`, where a panic formats, and verified by tripping it and reading the message. **Also from round 2:** `VC-R2`'s fix made `VC-R8` harder to see. Closing the visible two-call hole removed the prompt for the session-length question, so a reader now meets a mechanism that looks complete. A good fix can hide the next question. Both lessons are promoted into `26-sub-pr-design-discipline.mdc` rather than left here. |
| 2026-09-06 | **All four rulings RULED, relayed through the steering lane; `VC-1` widened to both integer authorities and re-pinned.** Provenance: the rulings reached this document as a relay quoting Rick, not as an in-channel signature — recorded as RULED with that provenance, per the standing rule that a relayed ruling is not a signature; an in-channel confirmation upgrades the rows without changing them. (1) tuple on `get_version` + one FFI byte, on **atomicity** — stronger than the coupling ground §3.5 had, and now stated there with its corollary for the genesis axis's second call; (2) `VC-2` in alpha.8, fold `VC-3`/`VC-4` including the fourth axis, four axes in the PR body's first paragraph; (3) typed `FakechainPolicy` default `Refuse`, no equivalence — the `SEEDHASH_EPOCH` shape, and the implicit-affordance defect that hid CEN-B5; (5) widen to both authorities before merge — `final_subsidy_per_minute` is the `FL-R12′` tail. Widened in this PR: canonical form `v2` with per-file section lines, `CANONICAL_FILES` walked by build script and tests alike, KAT re-derived in Python (`5e19c87d…`), live digest re-pinned (`6e1f9125…`), `economics_params.json` gains `_comment_digest`, economics C++ header byte-identical. Three carries recorded in §3.12: change detector not freeze; `VC-1` first, the `money_supply` rename re-pins; the 365 vs 365.25 year-convention grade (365 authoritative for emission arithmetic; FA-6's 365.25 horizon is a margin and may stay if it says so — FA-6's line to write). |
| 2026-09-05 | **Round opened; the problem is two no-consumer facts, not one.** The dispatch named `CORE_RPC_VERSION` (§0.1, re-swept: 31 hits, zero comparisons). Grounding the network axis found the second: `get_info.nettype` has no Rust reader, `WALLET_REWRITE_PLAN.md` :216 lock 5 requires the daemon's network "verified via `get_info` before any wallet operation", the landed `OpenError::NetworkMismatch` compares the wallet file to the caller and never asks the daemon, and `engine/daemon.rs:169`'s docstring says the check is performed when it is not (§0.2). The regtest e2e suite passing `Mainnet` wallets against `fakechain` daemons is the proof the check is absent. **Recorded because it changes the round's shape:** the network axis is not a nice-to-have beside the digest, it is a Phase-1 commitment that never landed and has been claimed in prose as landed since. |
| 2026-09-05 | **The digest is orthogonal to the network ID, not stronger than it.** The parent's §7 sketch said "stronger than a network-ID byte, because it commits to the rules rather than to a label". Half right: the constants file has no per-network data, so mainnet, testnet and stagenet share one digest. Identity is digest **and** network (§2); the design carries both and refuses on either. |
| 2026-09-05 | **"Local console fatal at startup" rejected: it cannot fail.** `Source::Live` renders from the same binary that would answer; comparing a constant to itself is a check that exists to be seen. The remote arm is the only console consumer (§3.6.1). |
| 2026-09-05 | **Refuse reads, not only submits.** Dispatch text allowed that refusing to read "may be merely annoying". Two grounds against: a rules mismatch means the read is of a different chain; a wire mismatch is where the open `#[serde(default)]` silent-zero lives. Both are wrong-data failures, not inconvenience (§3.6.3). |
| 2026-09-05 | **Scope held to design by steering direction** (alpha.8 slowdown; design docs exempt, wire changes not). Slices named in §4; `VC-1` identified as landable without a wire change; nothing started. Reported to the steering lane as a package before implementation, per its request. |
| 2026-09-05 | **`VC-1` built in this PR under the steering lane's ruling; the canonicaliser has one definition and two readers.** `shekyl-rpc-types/build.rs` and the crate's tests `#[path]`-include the same `build_support/consensus_canonical.rs`, so the generator cannot drift from its oracle. Which raised the question the mutation test answered: if both share the rules, what catches a rules drift? The KAT's expected digest was computed by an independent Python implementation of §3.3 (`json` + `hashlib`), so a mutated Rust canonicaliser disagrees with a number it did not produce — observed: a descending sort fails the KAT and the shape test while the build-vs-test agreement test stays green. And above that, the live-file sentinel turns the same mutation into a compile error before any test runs. Two independent oracles for one function, which is what "the check's subject cannot silently empty" costs to actually claim. |
| 2026-09-05 | **The digest's file set is a ruling, not an assumption (`VC-D12`).** The steering lane, correcting its own relay that the fee-ladder bundle would trip the new sentinel (it touches `economics_params.json`, a different file), exposed that nothing pins that file: `shekyl-economics`'s Blake2b digest is a fixture-lineage instrument covering 11 of its 18 keys and deliberately so. Proposed: one digest over both integer authorities, per-file sections, canonical form `v2`; a key rename moves it on purpose; `genesis_recipients.*` excluded because the genesis hash already commits to them (reopen if no client compares that either). Not built ahead of Rick's ruling — deciding what a "consensus constant" is for this project is his, and the one-file form is narrower than the surface rather than wrong. §6 gains ruling 5. |
| 2026-09-05 | **The genesis-recipients exclusion rested on a check nobody performs; the genesis hash becomes the fourth axis.** `VC-D12`'s first draft excluded `genesis_recipients.*.json` from the digest because "the genesis block hash already commits to them", with "reopen if no client compares it by `VC-4`" as the criterion. The steering lane checked: the criterion is a present fact — no Rust genesis-hash pin, no client comparison, only the daemon's own `GENESIS_TX`/`GENESIS_NONCE` in `cryptonote_config.h`. Verified here rather than relayed. Third stated-commitment-without-enforcing-site found today, and this one was this document's own. Disposition restated: the files stay out of the digest (per-network, non-integer), and the comparison joins `VC-4` as the fourth axis over the existing native `on_get_block_hash` — no wire change. `FAKECHAIN` shares mainnet's genesis, so `nettype` remains the regtest discriminator and the operator-readable value. **The convergence is the point:** the lock-5 wrong-chain case is undefended on network *and* genesis simultaneously; the tuple is the enforcing site for both. |
| 2026-09-05 | **A second false docstring, found by the steering lane's independent check of §0.2.** `engine/error/mod.rs:41` lists `OpenError::NetworkMismatch` as "wallet file says network N, daemon client says network M" under "variant names locked in by the plan" — and the variant's fields are `{ wallet, expected }`, with no daemon-reported value anywhere in the comparison. Recorded with `daemon.rs:169` in §0.2; `VC-4` fixes both in the same PR as the check. The lock finding now leads the package to Rick: not a new capability for alpha.8, but a defence the plan committed to and the wallet has shipped without. |

---

## 8. Review round 1 (2026-09-07) — `VC-R1`…`VC-R7`

Run at Rick's instruction, against this document and `VC-1` as built, on
`dev` `262c06ba9` + this branch, with `dev` re-read at `49b82b6df`. The round
was asked for because §6's rulings arrived as a **relay** rather than
in-channel, and because a document can be ruled without ever being attacked.
Two findings contest dispositions recorded as ruled; five are applied here.

| # | Finding | State |
| --- | --- | --- |
| `VC-R1` | The minor version this design reserved is already taken | **Applied** (§3.5) |
| `VC-R2` | The atomicity ruling and the genesis axis contradict each other | **Upheld 2026-09-07; applied** (§3.5) |
| `VC-R3` | The fakechain operator flag disables the only axis that sees regtest | **Upheld, carried further; applied** (§3.6.4) |
| `VC-R4` | "No arm where proceeding is better" is inherited from the API, not derived | **Applied** (§3.6.3) |
| `VC-R5` | The pin could not tell a developer what to re-pin to | **Applied** (code) |
| `VC-R6` | The genesis claim overstates what the digest attests | **Applied** (§3.7) |
| `VC-R7` | The console arm still counted three axes | **Applied** (§3.6.2) |

### `VC-R1` — 3.28 is gone, and this document is the reason to check

§3.5 said "at the anchor that is 3.28". `dev` now carries
`CORE_RPC_VERSION_MINOR = 28` and a `get_version_synced_v5.json` at
`196636`, landed by another lane while this document sat unmerged. The
document that warns "read `dev` at the moment `VC-2` is written, not at the
moment it branched" had itself gone stale on exactly that axis, in eight
days. **Applied:** §3.5 no longer names a number to use; it records that
3.28 was free at the anchor, is not free now, and that the value is read at
write time. The chain-delta test remains the mechanism that catches a
double-claim, and it caught nothing here because this branch never wrote the
constant — which is the correct outcome and worth saying, because "the test
did not fire" is not evidence the hazard did not occur.

### `VC-R2` — the atomicity argument, taken seriously, indicts the genesis axis

**The finding.** Ruling 1 put the tuple on one call because "two calls can
straddle a restart or a reconfiguration and return axes from different
states, so the client validates a tuple that never simultaneously existed."
That reasoning rejected reading `nettype` from `get_info`. But `VC-D12` then
put the **genesis** axis on a second call (`on_get_block_hash([0])`), and
§3.5's corollary defended it on the ground that block 0's hash cannot change
under a running daemon.

That defends the wrong proposition. The hazard is not that the *value*
changes between calls; it is that the *answerer* does. A daemon restarted
between the two calls can come back a different binary on a different chain;
a proxy or load balancer in front of two nodes can answer them from
different ones — and the RT posture explicitly supports a remote
`--daemon-address`, which is where such a middlebox lives. In either case
the client pairs `get_version` from daemon A with block 0 from daemon B and
accepts a tuple that never simultaneously existed, which is verbatim the
failure ruling 1 rejected. The corollary is a *narrower* claim wearing the
same words as the ruling.

**Disposition — UPHELD 2026-09-07, applied.** Carry the genesis hash as a fourth
`get_version` field. It is a fixed 32 bytes the daemon already holds
(`GENESIS_TX` / `GENESIS_NONCE` per network, `cryptonote_config.h:368`,
`:500`, `:511`), it rides a wire change that is already happening in `VC-2`,
and it makes all four axes one reply, one snapshot, no skew. The exception
then does not need defending because it does not exist. The cost is one more
field and one more `chain_facts` value; the alternative is keeping a
documented hole in the property ruling 1 was granted for.

### `VC-R3` — the fakechain flag disables the only axis that can see regtest

**The finding.** `FAKECHAIN` returns mainnet's configuration
(`cryptonote_config.h:562`). A `shekyld --regtest` daemon therefore reports
mainnet's genesis hash and, being the same build, mainnet's constants digest
and wire version. Three of the four axes are blind to it by construction;
**`nettype` is the only axis that distinguishes a regtest chain from
mainnet.** Ruling 3 provides for `FakechainPolicy::Accept` to be set by "the
harness or a named operator flag", and §3.6.4 proposes shipping
`--allow-fakechain-daemon`.

A shipped flag that turns off that one axis is a switch that lets a mainnet
wallet scan a fake chain with real addresses, reporting balances that are
not the user's — the lock-5 failure mode this round exists to close, restored
by a command-line option. Rule 21's standing observation applies with force:
a mode that exists gets used, and this one is a single flag between an
operator and a wrong-chain wallet.

**Disposition — UPHELD 2026-09-07 and carried further: the flag does not
exist at all.** Keep the typed policy; **reject the operator-facing flag**, with the reopening criterion being a *named*
operator task that requires it. `FakechainPolicy::Accept` stays reachable
only from the regtest harness (`regtest_e2e.rs`) and from tests, armed
in-process, so the affordance exists exactly where its need is demonstrated
and **nothing operator-facing ships**. Rick's addition: the harness
constructs the client, so it needs no CLI surface; a flag that exists only
for tests but ships in the production binary reaches a support forum as
"just add this flag"; and the asymmetry decides it — no flag costs a rare
workflow friction, the flag costs the only defence against a mainnet wallet
scanning a regtest chain a documented off-switch. This narrows
ruling 3 rather than contradicting it: its stated reason — the
`SEEDHASH_EPOCH` shape, armed explicitly and refused by default — is better
served by an affordance with no operator surface at all than by one guarded
by a flag's default.

### `VC-R4` — the uniformity claim is inherited, not derived

§1 asserts "there is no arm where proceeding is better than stopping". That
is true of this engine only because no offline open path exists: every
`open_*` takes a `DaemonClient` by value, so refusing at open removes nothing
a user has today. But the axes are not alike. Rules, network and genesis
mismatches mean *the data would be wrong*; a wire mismatch means *we cannot
converse reliably*, and a user whose node upgraded first is locked out of
their own wallet — history, export, backup — until one side moves.
**Applied:** §3.6.3 now names the residual, records that the own-node default
bounds it, and carries a reopening criterion tied to an offline open path.
The claim is no longer stated as a property of the axes when it is a property
of the API.

### `VC-R5` — the pin could not tell a developer what to re-pin to

**Observed, not reasoned.** `VC-1` shipped the live-file pin as
`const _: () = assert!(str_eq(CONSENSUS_CONSTANTS_DIGEST, "…"))`. Tripping it
deliberately produced:

```
error[E0080]: evaluation panicked: config/consensus_constants.json changed: its
canonical-form digest no longer matches the pinned value. Review the consensus
implications …, then re-pin here.
```

— an instruction to re-pin, with no value to re-pin **to**. A const-eval
panic takes a literal message and cannot format the computed digest, and the
failing assert makes the crate uncompilable, so the test that *would* print
both values cannot run either. The developer's only routes were reading a
generated file under `target/` or recomputing the digest by hand. A gate
whose remedy is not mechanically available is a gate people work around.

**Applied.** The pin moved into `build.rs`, where a panic formats. Verified
by tripping it again (`shekyl_tx_volume_window` 720 → 721, then restored):

```
the consensus-constant authorities changed: their canonical-form digest is now
    0c18687ad33708748bf9886f62a876df156e9477a47f49710dfb849b85318940
but this build pins
    6e1f9125232c522c475ef83b77799e11de6e7fc6e1867c261c83be4268026ab8
Re-pin `PINNED_DIGEST` in rust/shekyl-rpc-types/build.rs to the first value, and
answer the question the pin exists to force …
```

Build-time enforcement is unchanged — the same edit still fails the same
build — and the re-pin is now a copy. **The Decision-14 convention does not
transfer unexamined:** those sentinels pin small numbers a human can read in
the message (`DAA_TARGET_SECONDS diverged from 120`); a 64-character digest
is a value the message must *supply*, not merely name. `VC-1` adopted the
shape of the convention without checking that its reason survived the change
of subject.

### `VC-R6` — the digest attests the authorities, not the rules

§3.7 claimed that at genesis the comparison becomes an assertion of "rules
identity: every client and daemon that agree on the digest were built from
the same consensus constants". The digested set is two `config/` files, and
consensus-affecting values live outside them **by the authority's own
statement**: `_comment_daa` records that the LWMA-1 bias `99/200`, the
solvetime clamp and the min-L floor "deliberately do NOT live here" but as
literals in `lwma1.rs`. `C2-R2` §8 is queued to migrate the weight and fee
constants in from `cryptonote_config.h` — which is only a migration because
they are outside today. A daemon built from identical JSON and one patched
literal passes this axis while running different rules.

**Applied:** §3.7 now claims digested-authority identity, which is what the
mechanism can carry, and names full rules identity as available only once the
constants a rule depends on are all inside the digested set. That is a
precondition to be met, not a property to assume. **Same shape as the round's
founding finding** — a document asserting a check that the code does not
perform — here in this document's own claimed-property section.

### `VC-R7` — the console arm still counted three axes

§3.6.2 said the remote console "compares all three axes" after `VC-D12` made
them four; §3.6.3 had been updated and §3.6.2 had not. **Applied.** The
instance is small and the class is not: it is a rule fixed where it was
reported, which the parent slice recorded four times across four rounds.

### What the round did not find

No finding against the canonicalisation rules (§3.3), the one-definition
two-readers layout, the choice to compute the digest in `shekyl-rpc-types`
(`VC-D4`), the rejection of the local-console check (`VC-D6`), or `VC-1`'s
tests, whose reds were observed under mutation before they were trusted.
Recorded because "the round found nothing there" is a different statement
from "the round did not look there".

---

## 9. Review round 2 (2026-09-07) — `VC-R8`…`VC-R10`

Round 1's two open findings were **upheld**, `VC-R3` carried further than the
finding went. Round 2 is what round 1 did not reach, raised by Rick against
the round rather than against the document — the round's own blind spots —
and, with his in-channel signature on §6, two denominator questions against
ruling 5's wording (`VC-R11`, `VC-R12`).

| # | Finding | State |
| --- | --- | --- |
| `VC-R8` | Atomicity fixes the handshake and says nothing about the session | **Applied** — `VC-D13` |
| `VC-R9` | The tuple's parser is the first code to touch untrusted input | **Applied** — `VC-D14` |
| `VC-R10` | A digest mismatch cannot name the stale side | **Applied** — `VC-D15` |
| `VC-R11` | The digest's boundary is set by an adjective, not a stated decision | **Applied** — §3.12 coverage table |
| `VC-R12` | The `genesis_recipients.*` exclusion rests on a ruling that has not landed | **Applied** — §3.12 trigger |
| `VC-R13` | The pin's panic asks one question; a rename answers it wrongly and it points at deleting the constant | **Applied** — `build.rs` |
| `VC-R14` | The branch's index row failed a gate minted after the cut, and had never rendered | **Applied** — index row |

### `VC-R8` — one atomic call is a statement about one instant

`VC-R2` made the four axes one reply. That buys a true statement at the
instant of the handshake and **nothing about request 900**: the same
middlebox that could have straddled two handshake calls can pass the
handshake from node A and route the session to node B. Atomicity of the
tuple was never the same property as identity of the session, and ruling 1's
language implies the stronger one.

The finding's sharpest part is that **`VC-R2` made this harder to see, not
easier.** Closing the visible two-call hole removes the thing that would have
prompted the question, so a reader now finds a mechanism that looks
complete. That is a general hazard of good fixes and is worth carrying
beyond this document.

**Applied as `VC-D13`:** the claim is connect-time, stated as such, with what
an operator is expected to do about the gap (nothing on a local socket; on a
remote address the mechanism does not close it and the transport posture's
peer binding is where it closes). Connection pinning and per-request
revalidation are both named, both rejected for this round, with the reopen
criterion being a wallet holding funds expected to run against a daemon the
operator does not control.

### `VC-R9` — `get_version` is pre-validation, so its parser is the attack surface

`get_version` is definitionally the call made *before* anything is trusted,
so on the remote arm all four axes are attacker-controlled bytes. Comparison
is safe; parsing is not, and this crate carries both hazard shapes already.
Verified at source rather than accepted:

- `#[serde(default)]` — the finding said five sites in `chain.rs`; there are
  **eleven** attribute sites (`:242`, `:250`, `:271`, `:273`, `:275`, `:296`,
  `:317`, `:319`, `:351`, `:355`, `:359`). The correction runs toward more
  exposure, not less. The module's own doc at `:30` states the consequence:
  "**This is not a fix for silent defaults.**"
- `#[serde(other)]` — `lib.rs:217`, documented at `:38`. On `RejectCause` the
  collapse to `Unrecognized` is the *safe* direction; on `nettype` the same
  attribute would be the unsafe one.

Both convert "these disagree" into "these agree", the one outcome the design
exists to prevent. **Applied as `VC-D14`**, including that the requirement is
pinned by omission tests rather than by prose, that `DaemonNetwork`'s lack of
a `Default` makes one axis structurally safe rather than safe by review, and
that the rule is per-field on the tuple so it does not collide with the three
legitimate `KV_SERIALIZE_OPT` defaults the oracle vectors depend on.

**One citation corrected.** The finding offered `lib.rs:144` as the
"required, no default, stated reason" pattern to follow. That line is a doc
comment about a height field's lifecycle role and a carve-out from wire
minimalism; it is a field justified with a reason, not a no-default
requirement. The pattern `VC-D14` adopts is stated on its own terms rather
than by reference to it.

### `VC-R10` — a hash cannot say who is stale

Three axes can name the out-of-date side; the digest cannot, because a hash
carries no ordering. Shipping a message that says "these disagree" and
leaves the operator guessing which binary to replace is a real usability
defect in a refusal whose entire job is to be actionable.

**Applied as `VC-D15`, and not by picking one of the two offered
mechanisms.** The wire version names the side when it differs, which is free
and covers the common rebuild. When *only* the digest differs the refusal
**declines to guess** and says what the fact means instead — same RPC
contract, so neither side is a stale release; one tree's `config/` was
edited, which is a different rule set rather than a version skew. That case
is §0.4's middle row, the motivating case of the whole round, so answering it
with a fabricated ordinal would be worst exactly where the design matters
most. The monotonic constants-generation counter is rejected: hand-maintained
and forgettable, and a forgotten counter claims two rule sets are the same
generation, so it buys ordering precisely where its own reliability is
unverifiable. Reopen if constants ever change on a published schedule
post-genesis.

### `VC-R11` — "integer" was doing the work of a decision

Ruling 5 widened the digest to "both **integer** authorities". The adjective
set the boundary, so any consensus-relevant value that is not an integer was
excluded by a word rather than by a stated decision — and `VC-R6` had
already established that the boundary is real, since consensus values live
outside the digested files by the authority's own admission.

**Applied:** §3.12 now carries the boundary as a table — covered, refused at
the build, excluded with its cover named, and not covered — plus what the
uncovered set costs. The load-bearing part of the answer is that the
adjective is a **tripwire rather than a filter**: a non-integer value under a
non-`_` key fails the build naming file and key, so the day one appears the
build stops instead of the digest quietly shrinking. An adjective that
silently narrows a subject is the failure this finding names; an adjective
that refuses to narrow it is a different thing, and the difference had to be
written down to be checkable.

### `VC-R12` — an exclusion resting on an unlanded ruling

`genesis_recipients.*` are excluded because the genesis axis covers what
they determine. That axis does not exist yet: it ships in the folded
`VC-2`…`VC-4`. If the fold slips or the field is dropped, the exclusion
loses its cover and nothing in the tree says so — a cross-ruling dependency
carried as an assumption.

**Applied:** the dependency is now a named trigger. The exclusion is
conditional on `get_version.genesis_hash` shipping in the same change as the
digest's first consumer, which ruling 2's fold makes automatic; if the fold
is ever split the trigger fires and the files either join the digest or the
gap is recorded as accepted. **And the window before then is argued rather
than assumed away:** `VC-1` ships the digest with no consumer, so until the
folded PR lands nothing compares anything and an uncovered exclusion has no
consequence — an argument that holds only while `VC-1` stays consumer-less,
which is observable, because a consumer arriving early would be this round's
founding finding recreated in either direction.

This is the same shape as `VC-R2` and the first draft's genesis exclusion: a
disposition resting on a property that is stated but not yet enforced. Third
instance in this document alone, which is why the trigger is written as a
condition with a firing event rather than as a sentence of prose.

### `VC-R13` — the panic asked one question, and a rename answers it wrongly

**Found by the second reviewer against the pin's first live trip, and it is
the sharpest finding of either round.** The message told the developer to
answer *"does a different value of what moved make a different chain?"* — and
in the case that actually fired, `money_supply` → `emission_curve_asymptote`
at a byte-identical value, **no value moved**. Answered as written the answer
is "no", and the panic's own next sentence then reads "the constant does not
belong in these files". **The failure text steered toward deleting a
genesis-frozen economic constant from its authority.**

This is `82-failure-mode-ux.mdc` at its narrowest: a message that only ever
fires at a moment of confusion has to be right in *every* case it fires, and
on its first real trip this one misdirected. That it did not misdirect *me*
is not evidence — I wrote the ruling that says a rename is expected, so I
answered from the design rather than from the message. A reader without that
context follows the text.

**Applied.** The panic now branches on what moved and says how to tell:
`git diff` the two files against the pinned tree, then read off the case. A
**value** change asks the chain question and can legitimately conclude the
constant does not belong. A **rename** at an unchanged value moves the digest
*by design* (`VC-D12`), so the instruction is re-pin and keep the constant,
asking the chain question of the value the new name binds. An **added or
removed** key asks the chain question of that key. No case now ends at
"delete a constant" by default.

**Recorded as a class, because the first fix had the same shape.** `VC-R5`
fixed *what the message could say*; this fixes *whether what it says is
right*. Both are the diagnostic failing rather than the check failing, and a
check can be correct on every input while its diagnostic is wrong on the
input that actually arrives.

### `VC-R14` — the branch's own index row failed a gate minted after the cut

`check_index_table_shape.py` arrived on `dev` with `docs-gates.yml` while
this branch was unmerged. The branch's VC row carried **three cells against
a two-column header**: GFM drops the surplus, so the status half **had never
rendered** — and inside that invisibility it had gone stale, still reading
`VC-D1…VC-D12` and "round 2 (2026-09-06)" against a document at `VC-D15`
with rounds signed on the 7th. Exactly the decay the gate was minted to
catch, on the row this branch added.

**Applied:** the row is two cells, with the status folded into the
description where it renders.

**The general failure is mine and it is worth naming: I was running a gate
list, not the gate directory.** Nine names, carried forward from when I
learned them, against **17** `scripts/ci/check_*.py` in the tree — eight I
had never run. (Scope and unit, since this document now has a rule about
that: 17 gate *scripts* matching `check_*.py`; `scripts/ci/` holds 50 files
in total, and the CI workflows invoke a subset of the scripts by name.) A
gate set is a moving denominator and enumerating the directory costs one
command. All 17 now pass; the one I had never run caught a real defect on
its first execution, and the citation ratchet — which refuses to run at all
against unfetched submodules — passes at the `origin/dev` baseline once they
are initialised, so this branch adds no dead citations.

### What round 2 did not find

No finding against `VC-D13`…`VC-D15` themselves (they are this round's
output, and their own review is round 3's if there is one), against the
canonicalisation rules, or against `VC-1` as built after `VC-R5`. Recorded
per the denominator discipline this round promoted into
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
"the round found nothing there" is a different statement from "the round did
not look there", and only the first is evidence.
---

## 10. Review round 3 (2026-09-08) — `VC-R15`…`VC-R22`

A second reviewer's pass over the PR, run against `6c6b565da` and answered
against the merged tree. Three required corrections and five "why" questions
that the reviewer asked be answered **here** rather than re-derived inside
`VC-2` — two of which change `VC-2`'s shape and would have been expensive to
reverse after its ABI pin landed.

| # | Finding | State |
| --- | --- | --- |
| `VC-R15` | The §2 family registry row was dropped by my own merge resolution | **Applied** — restored |
| `VC-R16` | The digest is typed `String` where `HashHex` is the canonical helper | **Applied** — §3.5 |
| `VC-R17` | Identity facts were to widen the **tip** POD; wrong seam | **Applied** — §4 |
| `VC-R18` | The independent oracle was authoring-time, not CI-time | **Applied** — new gate |
| `VC-R19` | Economics keys ingested wholesale without a per-key membership grade | **Applied** — §3.12 |
| `VC-R20` | Lock 5 still names `get_info` as the carrier | **Applied** — `VC-4` row |
| `VC-R21` | Ruled dispositions still described in proposal voice, in four places | **Applied** — swept |
| `VC-R22` | No policy for when `get_version`'s **own shape** is what changed | **Applied** — §3.16 |

### Numbering, because two reviews numbered the same findings differently

The reviewer's pass numbered its findings `VC-R14`…`VC-R19`; those numbers
were already taken in this document by rounds 1–2 (`VC-R13`, `VC-R14`). The
tree's numbering is the one that is committed, pushed and cited from code, so
it stands, and the map is recorded here rather than left for a reader to
infer from prose:

| Reviewer's | This document's | Subject |
| --- | --- | --- |
| `VC-R14` | **`VC-R16`** | `String` where `HashHex` belongs |
| `VC-R15` | **`VC-R17`** | identity facts in the tip POD |
| `VC-R16` | **`VC-R19`** | per-key membership grade |
| `VC-R17` | **`VC-R18`** | the Python oracle is a claim, not an artifact |
| `VC-R18` | **`VC-R20`** | lock 5 still routes through `get_info` |
| `VC-R19` | **`VC-R21`** | ruling 5 carries the falsified prediction |

Renumbering to match would have moved identifiers that `build.rs` and
`consensus_digest.rs` already cite, which is the cost rule 94 exists to
avoid — a token that means one thing in the tree and another in a review is
worse than two numbering schemes with a stated map.

### `VC-R15` — I dropped the family row while resolving my own merge

Rule 94's registry row for `VC-` was **gone**. Resolving the
`IMPLEMENTATION_INDEX.md` conflict, I took `dev`'s file and re-inserted the
row I remembered — the documents-table row — and the §2 family row was the
one I did not. The family existed in a document, in code and in a PR, and not
in the registry that exists so a reader can find out what `VC-` means.

**The prefix-uniqueness gate passed throughout, and could not have failed:**
it checks the rows that are present for collisions. A *missing* row collides
with nothing. A census cannot see an absent subject, which is why rule 94
puts the obligation on the PR that mints the family rather than on a checker.
**Restored, current** (`VC-D1…VC-D15`, `VC-R1…VC-R22`, five cells matching the
§2 header). The lesson is narrower than "be careful merging": *reinserting
from memory is a recall test, and the thing you are recalling is exactly what
the conflict destroyed*. The resolution should have been a diff of my side's
`VC-` rows against the result, which is one command.

### `VC-R16` — `String` where `HashHex` exists

The digest field was typed `String`. It is a SHA-256 — 32 bytes, 64 lowercase
hex — which is precisely `hash.rs`'s subject, and that module's doc says why
it exists: before RK-3 such fields were `String`, "which made *not a hash at
all* a value the type admitted". A `String` digest reintroduces that on the
field least able to afford it: it **false-mismatches on uppercase hex**,
reporting a rules disagreement on the axis whose job is precision about
rules, and it lets `"nope"` arrive at the comparison as data instead of being
refused at the parse. **Applied:** `HashHex`, which refuses any length but 64
and any non-hex character, accepts either case, and re-emits lowercase — so
`VC-D14`'s strictness is delivered by the type rather than by a remembered
rule. A missed reuse of a canonical helper is not a style point when the
helper was minted to close this exact defect.

### `VC-R17` — the identity facts do not belong in the tip POD

`VC-2` was to widen `ChainTipFactsFfi` with `nettype` and 32 genesis bytes.
Neither is a tip fact: they are process and configuration identity, constant
for a daemon's lifetime, while the tip changes every block. `chain_tip()` has
**six** call sites, and `get_height` / `get_block_count` want none of this.
The POD already carries one `get_version`-only hitchhiker — `release_build`,
whose own comment at `chain_facts.rs:28` admits it "rides the same POD
because `get_version` reports" it — and the widening is that exception
growing by 33 bytes on every tip read.

**Applied: a separate identity POD.** The decisive point is that **atomicity
is about round trips, not FFI calls** — two FFI reads inside one
`get_version` handler still produce one RPC reply from one snapshot, so
nothing in ruling 1 requires them to share a struct. Splitting also *shrinks*
`VC-2`'s ABI blast radius: the tip POD's layout twins and offset pins do not
move at all, and the new pins cover a struct with one purpose. The pre-flight
correctly flagged the cost of widening the tip; it did not ask whether the
tip was the right seam, which is the question that mattered.

**Not moved:** `release_build`. Relocating an existing field is a separate
change with its own ABI cost and no bearing on this round. **Reopen** when
something else needs the identity POD, at which point the hitchhiker has a
natural home.

### `VC-R18` — the second oracle was independent when written, not when run

§8 called the Python-computed KAT digest what "catches a rules drift both
`#[path]` readers share". Measured rather than assumed: the KAT **does** catch
a Rust drift on its own — a reversed key sort fails it — because its expected
form and digest are frozen literals. What it cannot catch is a drift where
those literals move in the same edit, which is two lines in one file. Their
independence was historical: it protected the *value*, not the *rules*.

**Narrowed in the finding's favour, then applied.** The gap is not total:
`the_live_canonical_form_has_the_shape_the_design_pins` asserts the form's
*structure* independently of any digest — bytewise key order, plain decimals,
no prose leak, `key SP value` — so a reversed sort or a separator change reds
without the KAT's help. What the KAT alone protects is the **digest arithmetic
and the header version**, and those are exactly the two an editor moving both
`#[path]` readers would also move.

**And the artifact exit was taken for a reason outside testing.** The digest
is a **wire fact**: once `VC-2` ships, any third-party client must be able to
recompute it, so a tree-resident, language-neutral reference implementation is
something this project owes that audience regardless of CI. Written for that
purpose it costs about forty lines, and running it against the generated
constant is then a free second use rather than the whole justification.

`scripts/ci/check_consensus_digest_oracle.py` re-implements §3.3
from the design text, recomputes every run, and compares to `build.rs`'s
`PINNED_DIGEST` — so there is no expected literal to move alongside the
implementation, and a silent move now requires editing two implementations in
two languages. It self-tests both directions, asserts its own subject exists
(a renamed or absent `PINNED_DIGEST` fails rather than passing over nothing,
rule 47), and is wired into `docs-gates.yml` with the two authorities and the
pin as its trigger paths. **Verified by construction:** with the Rust
canonicaliser reversed and the pin updated to match — the exact edit the
frozen literals would miss — the gate reports the disagreement.

### `VC-R19` — the economics file was ingested wholesale, ungraded

`VC-R11` closed "integer" doing the work of a decision for the *type* of
values. It did not ask the same question of the *keys*. `display_decimal_point`
is a display convention coupled to `coin` by a units assert: a different value
of it, alone, does not make a different chain. `shekyl_blocks_per_year` feeds
`calc_effective_emission_share` and does. The pin treats them identically.

**Applied, and deliberately *not* by filtering.** The grade is recorded, and
the disposition is that the digest's subject stays **the whole file**:

- A filter is the silent-shrink hazard `VC-R11` just closed, wearing a
  different name. A per-key allowlist would need maintaining, and a key
  dropped from it is invisible.
- Over-inclusion is the **fail-safe direction**: a display key in the set
  costs a spurious re-pin — and, post-`VC-2`, a spurious refusal — but never a
  missed rule change. Under-inclusion costs the opposite, and the opposite is
  the failure this whole round exists to prevent.
- **The membership rule (§3.7) binds what goes *into* the file, not what the
  digest reads out of it.** A key that fails the grade is a finding against
  `economics_params.json`'s contents, owned by that file's owner, and the
  right remedy is moving it out — not teaching the digest to look away.

So the grade's product is a question for the economics owner, recorded here
rather than acted on unilaterally: **does `display_decimal_point` belong in a
consensus authority at all**, given it is a rendering convention? Until that
is answered it stays digested, which is the safe side of the error.

### `VC-R21` — ruled dispositions still speaking in proposal voice

Four live instances, not the one reported: `VC-D2` still opened "**Proposed:**";
§3.5's corollary, §3.6.3 and §3.12 all still described the genesis axis as
riding `on_get_block_hash([0])`, which `VC-R2` had removed. Swept together,
with the historical mentions (the decision log, the round sections, the "as it
stood before `VC-R2`" sentence) deliberately left as records-was. §6's ruling 5
also still carried the sequencing prediction that §3.12 and §7 had already
recorded as falsified — a signed-ruling table is the next reader's starting
assumption, so a false note there outranks a false note anywhere else.

### `VC-R22` — what happens when `get_version`'s own shape is what changed

The tuple is compared *after* the reply parses. `VC-D14` makes every tuple
field strict and the reply type carries `deny_unknown_fields`, so a daemon
whose `get_version` shape has changed produces a **deserialization error, not
an identity refusal** — and the design said nothing about it. That is the
handshake's own bootstrap case, and it is not rare: it is what a wire-version
skew *looks like* on the one method the client calls first. **Applied as
`VC-D16`** (§3.16).
