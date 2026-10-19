# Chain sync — headers-first sync in Rust: Round 0 (`CS-`)

**Families (registered in `IMPLEMENTATION_INDEX.md` §2, rule 94):** **`CS-Q`** (questions, ruled here) and **`CS-F`** (findings). Grep surface: `rg -n -e '\bCS-[QF]'`, because the serve-credit findings family `SCS-F` contains `CS-F` as a substring. `CSR-` is a separate family.
**Ground:** `dev` at `52b3c73bb` (2026-10-18), after #1101 (DRS-X Round 0), #1088 (the daemon-config cutover) and #1102 (the Rust pool). The handler is 2,669 + 228 lines; `block_queue` is 651 (`.h` 115 + `.cpp` 536); `cryptonote_protocol_defs.h` is 300.
**Status:** OPEN — Round 0 RULED, Rick 2026-10-18: CS-Q1…CS-Q12 as recommended, with four amendments: the complement request is chain sync's (CS-Q1, CS-Q10); `Synced` reads verified headers only (CS-Q2 step 7); the long-run slot is paid for in PoW and goes to the most verified work (CS-Q2 step 3); `following_degraded` gets a Rust producer (§A, coupling 4). Nothing here is implemented; the pure-Rust work of CS-Q10 starts first.
**Parent:** [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.2, row **CS**. [`DRS_X_STORE_FLIP.md`](DRS_X_STORE_FLIP.md) carries §A below as chain sync's Round 0 requirement.

**Subject.** Moving chain sync (`cryptonote_protocol_handler`, `block_queue`) from C++ to Rust.

**What is not in this document.** The block-arrival entry into Rust ingest
belongs to DRS-X (R2, 2026-10-15; `626cadea2` renames "E3's p2p feed" to
DRS-X). §A states what chain sync needs from that entry. **DRS-X has
adopted it, landed on `dev`:** `DRS_X_STORE_FLIP.md` takes it up in DX-Q2
items 2, 3, 5 and 6 (`:58-73`), "carried here", and assigns CS-F5's doc
fix to its PR 2 (`:292`). §A records the couplings that remain.

---

## Findings that shape the questions

- **CS-F1. The handshake sync payload can never be refused.**
  `process_payload_sync_data` (`.inl:399-474`) returns `true` on every
  path. So the dialer's `PayloadRefused` (PR-3) is unreachable today.
  Chain sync owns what "refuse" means (CS-Q2).
- **CS-F2. Chain work is never consulted.**
  - The handshake's `cumulative_difficulty` is passed through by
    `on_outbound_handshake` (`net_node.inl:857-864`) and never read.
  - `RESPONSE_CHAIN_ENTRY.cumulative_difficulty` is never read either.
  - The sync target is the highest *claimed height* (`.inl:456`,
    `:1052`, `:2475`).
  - `m_synchronized` is a latch: it is set once (`:2244`) and never
    cleared.
- **CS-F3. Body-first sync plus the reorg cap can strand a fresh node.**
  - The C++ downloads and connects bodies along whatever hash list a
    peer sends, before any chain-work comparison.
  - The Rust alt tier refuses any switch deeper than `D_max`:
    `Offered::BeyondCap` and `Switched::BeyondCap` (`switch.rs:122`,
    `:336`). `D_MAX` takes `archival_reorg_depth_blocks`, which is
    provisional at 720 blocks (`config/consensus_constants.json`). That
    is 24 h at `daa_target_seconds = 120`.
  - Consequence: a node eclipsed during initial sync connects the
    attacker's chain. Once that chain is more than `D_max` deep, the
    node can never follow the honest heavier chain, even after it sees
    it.
- **CS-F4. Two outbound-composition levers survive PR-3.**
  - `needs_new_sync_connections` (`.inl:2546`) has had no caller since
    `gray_peerlist_housekeeping` was deleted.
  - `update_sync_search` (`.inl:1695`, `on_idle`, every 101 s) still
    drops a synced outbound peer whenever outbound is full and fewer
    than 2 peers are syncing. The dialer then refills the slot. So C++
    still drives composition beside the dialer.
  - **The two comparisons are in Rust; the levers are still C++.**
    - `rust/shekyl-ffi/src/sync_ffi.rs`: `shekyl_sync_room_for_syncing_peer`
      and `shekyl_sync_wants_more_outbound`, read against the dialer's
      target (`DAEMON_CONFIG_CUTOVER.md` §4.2, "the reverse pulls").
    - `SYNC_SEARCH_CONNECTIONS = 2` there duplicates
      `P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT`
      (`cryptonote_config.h:197`), which still exists.
- **CS-F5. The ingest docs disagree with the landed switch.**
  - `source.rs:28` says "DRS-X's p2p source computes the heavier-chain
    switch". `:43` says the p2p feed "emit[s] `Rewind`".
  - The landed `switch.rs` puts the fork choice and the pops inside
    ingest's alt tier (`OfferAlt` → `SwitchPlan` → `Reorganize`).
  - **CS-Q2 below follows the code.** The doc fix belongs to the DRS-X
    lane, which has taken it into its PR 2.
- **CS-F6. The wire can be headers-first with no new primitive.**
  - `Block::pow_blob()` is `header ‖ tx_tree_hash ‖ V(count)`.
    `identity_of_pow_blob()` names the block from that alone
    (`shekyl-wire/src/block.rs:237-271`).
  - Difficulty is `lwma1_next` over timestamps and cumulative
    difficulties only.
  - `ReleaseAnchors` is a genesis hash plus a static table of
    `(height, hash)` anchors (`shekyl-chain-rules/src/anchors.rs:114`).
  - So a header chain can be checked for linkage, PoW, difficulty,
    timestamps and anchors without any bodies.
- **CS-F7. Validation runs on the p2p I/O pool.**
  - `try_add_next_blocks` validates on the strand that holds
    `m_sync_lock`.
  - The executor has 2 workers (`net_node.inl:495-500`), and one of them
    is blocked by `idle_worker`.

---

## CS-Q1. The boundary

**Problem.** The handler mixes four jobs:
- getting blocks we don't have (sync);
- propagating new blocks at the tip;
- transaction relay;
- connecting blocks to the store.

Three lanes touch it (RD, slice 4 and DRS-X), and none is named as the
owner of block propagation.

**Question.** Who owns which function, and what is each function's fate?

**Ruled (Rick, 2026-10-18):** the table below.
- **Block propagation is chain sync's.** That covers the compact-block
  announce, `relay_block` and the missing-tx pair. The reasons:
  - An announce is the event that drives sync at the tip: an `Unlinked`
    reply to an announce *is* the start of a sync.
  - D++ privacy, which is RD's scope, is about transactions; blocks
    carry no origin to protect.
  - The alternative splits "blocks arriving from peers" across two
    owners who share the ingest entry and the handling of failures.
- **The transaction routes are RD's,** and so is serving the pool
  complement: they are transaction movement. **The complement request is
  chain sync's:** it is sync's own event (the transition to `Synced`)
  and its own Levin send (CS-Q10). `DRS_X_STORE_FLIP.md` §4 item 6 is
  amended to match (§A, coupling 1).

| C++ function | Owner | Fate |
| --- | --- | --- |
| `handle_request_chain`, `handle_response_chain_entry` | CS | Redesign (headers, CS-Q3) |
| `handle_request_get_objects`, `handle_response_get_objects` | CS | Redesign (byte budget, body form by height, CS-Q3) |
| `request_missing_objects`, `should_download_next_span`, `skip_unneeded_hashes`, `request_chain_history`, `calculate_dynamic_span`, `block_queue` | CS | Redesign as the sync owner's scheduler (CS-Q2, Q8) |
| `try_add_next_blocks` (the add loop), `make_*_connect_supplement` | DRS-X | Deleted here. Arrivals go to the DRS-X entry; formation is `form`'s |
| `process_payload_sync_data` | CS | Redesign as hint intake. Callers: the dialer's result (landed) and slice 4's inbound handshake and timed sync |
| `get_payload_sync_data` | — | Delete. The dialer already reads `shekyl_core_publish_tip`; slice 4 reads the same snapshot |
| `on_connection_synchronized`, `is_synchronized`, `is_busy_syncing`, `m_synchronized` | CS | Redesign as one derived, published sync state (CS-Q2). The edge it fired into the pool complement is replaced as in CS-Q10 |
| `on_connection_close` | CS | Keep the job (a closed session's requests are re-queued). The target recompute is deleted |
| `kick_idle_peers`, `check_standby_peers`, `on_idle`, `on_callback` | — | Delete. They become per-request deadlines on the timing engine (CS-Q4); no polling |
| `update_sync_search`, `needs_new_sync_connections`, and their Rust verdicts in `rust/shekyl-ffi/src/sync_ffi.rs` (landed Rust) | — | Delete at the CS cutover (CS-Q7), the landed Rust half included |
| `handle_notify_new_compact_block`, `relay_block`, `handle_request_compact_missing_tx` | CS | Redesign: announce → entry; relay after the entry's `Connected` |
| `handle_notify_new_transactions`, `relay_transactions` | RD | Untouched by CS |
| `request_txpool_complement` | CS | Redesign: the sync owner sends the request from Rust at its transition to `Synced`; the reply, `NOTIFY_NEW_TRANSACTIONS`, goes through RD's route (CS-Q10) |
| `handle_notify_get_txpool_complement` | RD | Serving the complement stays RD's |
| `hit_score`, `drop_connection_with_score`, `drop_connections`, the `add_host_fail` calls | — | Per CS-Q5 |
| `shekyl-peer-policy`'s `BlockIngest`, `BlockAnnounceAction`, `BlockSyncAction` and their FFI predicates (`peer_policy_ffi.rs`, `block_ingest.h`; landed Rust, PWD-B7) | CS | **Keep and extend additively.** CS-Q2's mapping from the entry's reply to an action is built in this crate, under PWD-B7's tri-state verdict (CS-Q4). Only the `heavier_score` arm (`block_peer.rs:103`, `:175`; used at `.inl:649`, `:1512`) retires, per CS-Q5. The C++ predicates go with the sync half |
| Sync-time estimate pair, `cumulative_block_sync_weight` | CS | Redesign. Progress is read from the header chain (rule 80). The Monero mainnet size table is deleted (rules 60, 71) |
| `log_connections` | console | Delete. The console reads the board |
| `safesyncmode`, the `pause_mine`/`resume_mine` coupling | — | Delete. `safesyncmode` is an LMDB knob and leaves with DRS-X; the miner reacts to tip changes, not to sync |
| `dev-sync` (was `--no-sync`; `INPUT_GRAMMAR.md:260`, "the chain-sync lane owns it"; regtest only) | CS (data) | Keep as the grammar has it: with `dev-sync = off` the sync owner is not started. Read from the snapshot (`net_node.inl:429-430`) |
| `prep-blocks-threads`, `block-sync-size`, `span-limit`, `block-download-max-size` (`INPUT_GRAMMAR.md:270`, **L** chain-sync), and the hardcoded `m_block_download_max_size = 0`, `m_span_time = 2` (`.inl` `init`) | CS | Per CS-Q12 |

**Wargame.**
- **Remote trigger or benefit.** None. This is an ownership question.
- **Risk.** A gap between owners. The table is total over the handler's
  surface, and the deletion `rg` (CS-Q9) asserts nothing is left.

---

## CS-Q2. The model: the sync state machine

**Problem.**
- The C++ protocol is "trust the claimed height, download a hash list,
  fetch bodies, connect".
- Sync state is spread across `m_state` on each connection (which also
  serves as the session-lifecycle flag), a latch, and a target that is
  the maximum claim.
- Ruling B makes the model, not the C++, the reference the
  implementation is tested against.

**Question.** What state machine does Rust sync implement?

**Ruled (Rick, 2026-10-18): headers-first, select by verified work, with
ingest deciding forks.**

**State.**
- **Global.**
  - The local tip `L`, from the store.
  - A header tree `T` of verified headers.
  - The best chain `H*`: the most cumulative work among the
    **reachable** chains in `T`, meaning those whose fork point with `L`
    lies within `D_max`.
- **Per session.**
  - the peer's claim (height and cumulative work, a hint only);
  - its verified frontier in `T`;
  - its **run**: headers received but not yet PoW-verified, held within
    a per-session byte budget;
  - at most one outstanding request with its deadline.

**Steps.**
1. **Hint.**
   - A handshake payload (from the dialer, or from slice 4 inbound) or
     an announce is a *claim*.
   - A claim whose work exceeds `work(H*)` makes that session a header
     source.
   - **Refuse the payload only if it is structurally impossible:**
     - height 0 (every chain has genesis);
     - cumulative work below `GENESIS_DIFFICULTY`. Every chain's work
       includes its genesis block's, and `GENESIS_DIFFICULTY > 1` is
       const-asserted (`shekyl-difficulty/src/consts.rs:101`).
   - That is the whole meaning of `PayloadRefused` (CS-F1).
   - There is no height ceiling: no protocol maximum exists, and a bound
     derived from the clock is weak, because the MTP rule lets timestamps
     advance slowly.
   - A claim is never a target.
2. **Common ancestor.**
   - Send a sparse locator from our main chain.
   - The peer answers with headers starting at the first locator hash it
     holds.
   - The first header's parent must be in the store (main or alt) or in
     `T`. If not, the response is a protocol violation.
3. **Verify headers: cheap checks per response, then the work test on
   the run, then PoW.**
   - **Cheap checks, on each response as it arrives, at almost no
     cost.** Any failure closes the session.
     - linkage;
     - timestamp rules (MTP from the chain, FTL against the local clock);
     - `ReleaseAnchors` (CEN-E1);
     - each header's difficulty from `lwma1_next`, which needs only the
       chain's timestamps and work.
     - Headers that pass are added to the session's run. So the run's
       cumulative work is exact before any hash.
   - **The work test is on the run, not on one response.** Responses
     are byte-budgeted (CS-Q3.1), so an honest first response is only a
     prefix of the peer's chain.
     - **The run's work exceeds `work(H*)`:** go to PoW.
     - **The peer says it has no more headers, and the run's work falls
       short of its claim:** the session is closed, with zero hashes.
       This is the liar.
     - **The peer has no more, and the run's work is at most
       `work(H*)`:** the run is dropped and the session is kept. This is
       an honest lighter fork, or a peer that is behind.
     - **The run fills its per-session budget without exceeding
       `work(H*)`:** the run is dropped with zero hashes, and the
       session is not asked again until its claim changes.
       - Until then, the most the session costs us is the budget.
       - The budget's value is an `Assumption` (CS-Q11).
     - **What the budget must cover.** A run has to reach from its fork
       point to past `H*`'s tip before its work can exceed `work(H*)`.
       - **At the tip,** that is at most `D_max` headers: about 144 kB at
         200 B each.
       - **In initial sync,** it can be the whole chain. Example: one
         session has already filled `T` with 100k headers, and an honest
         heavier chain forks from it near genesis. That is about 20 MB,
         and it is exactly the case CS-Q4 (c) defends.
       - A per-session budget of `D_max` headers would drop that honest
         run, so it is not enough. One the size of `T` for every session
         would be too much on a Pi 4: 64 sessions × 20 MB is about
         1.3 GB.
     - **The rule: PoW deferred within the budget, paid to grow past it.**
       - **Within its own `D_max` budget,** a session's run defers PoW
         as above. An honest lighter fork costs zero hashes.
       - **One shared long-run slot** lets a single run grow past
         `D_max`, up to the size of `T`. A run that fills its budget
         without exceeding `work(H*)` may claim the slot. To take it,
         it verifies the PoW of its deferred prefix. Once in the slot,
         it pays PoW on **each response as it arrives**.
       - **The slot goes to the run with the most verified work.** A
         waiting run takes the slot over when its verified work exceeds
         the holder's verified work **at the same height**, the waiting
         run's verified frontier. A displaced run is dropped back to its
         budget, and its session is kept.
       - The comparison is at equal height because a waiting run is
         capped at `D_max` headers and could never out-total a holder
         that keeps extending.
       - So holding the slot costs real PoW. A run of cheap,
         low-difficulty headers loses the slot to an honest run that is
         heavier at the same height. A holder that is not displaced
         still ends: within the size of `T`, or at a missed deadline.
       - Headers in the slot join `T` only when the run's work exceeds
         `work(H*)`, so verified but lighter headers never grow `T`.
       - The memory bound is about `2 × |T|`, plus `D_max` headers per
         session.
       - **Not taken: Bitcoin Core's presync and redownload,** which
         keeps a small commitment per header and fetches the run again
         once its work is proven. It needs less memory, but it is a
         second protocol pass. *Reopen if* the Pi 4 figures (CS-Q11)
         show `2 × |T|` does not fit.
   - **PoW, last.** RandomX (with the seed from the header chain
     itself) on each header of the run, in order.
     - The first failure closes the session.
     - Headers that pass join `T`, and the run is cleared.
4. **Select.** `H*` = the most work among the reachable chains in `T`.
   - A liar who claimed more work than its headers deliver is caught at
     the end of its run (step 3) and its session is closed.
   - The claim is never trusted.
5. **Bodies.**
   - Request bodies along `H*` only, in spans.
   - A span goes to any session whose verified frontier covers it.
   - One request is outstanding per session, under a global byte budget.
   - Arrivals go to the DRS-X entry in chain order.
6. **Verdicts** from the entry's reply (§A):
   - `Connected`: advance.
   - `Refused`: mark that header and its subtree in `T` invalid and
     close the session that served the body. A new `H*` follows.
   - `Unlinked{at}`: re-locate from `at` (a tip announce whose parent we
     lack).
   - `NoRoom`: the entry refused before acceptance. Sync keeps the span
     within its byte budget and offers it again when the entry reports
     room. It is never a fault of the peer. It arises only from the race
     between asking for room and offering.
   - `Held`, `SwitchDue` and the switch outcomes: ingest's. Sync only
     reads the new `L`.
   - `BeyondCap`: arises only on the **announce path**, because bodies
     are requested only along reachable `H*`. It feeds the `Diverged`
     alarm below, and it is not that alarm's primary source.
7. **State, published as one source.** **A claim's value never changes
   the sync state; only verified headers do.** A higher claim only starts
   a header request (step 1).
   - **`NoView`**: no session has completed a handshake.
   - **`Behind { have, best }`**: `work(L) < work(H*)`, over verified
     headers.
   - **`Synced`**: not `NoView`, and `work(L) ≥ work(H*)` over verified
     headers.
   - **Why no "a peer agrees" condition.** Reading it as "peers name our
     tip" would stop mining during an ordinary equal-work tip race.
     Reading it as "a higher claim means we are behind" would let anyone
     rotating sessions halt mining and transaction intake.
   - **`Diverged { fork_at }`**: an **alarm** carried beside the state,
     not a state of its own.
     - **Primary source:** `T` holds a verified chain that is heavier
       than `L` and forks deeper than `D_max`. Those headers pass the
       same step-3 run, so raising the alarm costs no more than any
       other header chain. A claim alone never raises it.
     - **Secondary source:** an announce answered `BeyondCap`.
     - It never withholds `Synced`, and it never stops the miner or the
       relay gate (CS-Q4).
     - **Its wire is the existing `following_degraded`** (C2-R1b F-1(a);
       `get_info.health.following_degraded`, `CORE_RPC_VERSION` 3.26).
       That flag is set today by a switch refused at the prune watermark
       (`m_following_degraded`, `blockchain.h:1071`, set at
       `blockchain.cpp:2288`).
     - It already has a wallet-side consumer:
       - the stake engine reads it as `NotFollowing::Degraded`
         (`shekyl-engine-core/src/engine/stake_engine/serving/daemon_tip.rs:276`);
       - that file records that it relies on the flag being one-way:
         "this refusal latches until a resync; that is the direction we
         want".
     - **Reused, not a second alarm** (ruled). Two consequences:
       - (a) **The field's meaning widens,** from "a switch refused at
         the prune watermark" to "a heavier chain refused at either cap:
         the undo floor (`Switched::BelowFloor`) or `D_max`
         (`BeyondCap`)". Both mean the node knows it is not on
         the heaviest chain it has seen, which is what the wallet
         consumer acts on.
       - (b) **The latch stays.** The alarm latches until a resync, as
         C2-R1b ruled and the wallet relies on. `NoView`, `Behind` and
         `Synced` stay derived.
         - A derived alarm would also clear on restart, because `T` is
           held in memory, until the heavier chain is seen again. That
           is the wrong direction for a fault that needs an operator.
         - If the latch must survive a restart, it is a persisted flag:
           one bit in the store, the store lane's to place.
           C2-R1b's latch is process-lifetime today.
     - **Its producer is Rust:** a latch that ingest sets from the flip
       and the sync owner also sets from the CS cutover (§A, coupling 4).

   **The consumers:**
   - the RPC (`synchronized`, plus `target` as `null` when unknown, per
     RK, plus `following_degraded` for the alarm);
   - RD's relay gate;
   - the miner;
   - the sync owner's own complement request (CS-Q10);
   - **the wallet (rules 81, 82).** An eclipsed node under the alarm
     still reports `Synced`, so the alarm must reach the person whose
     funds ride on that chain, not only the operator's console.
     - The stake engine already reads `following_degraded` (above).
     - Outside the stake engine, no wallet code reads it. Its other
       hits, `synced_chain_facts.rs:542` and `shekyl-cli/src/daemon.rs:469`,
       only build a response with it set to `false`.
     - Showing it to the person in plain terms is the wallet lane's. The
       engine's `AlarmBoard` (`shekyl-engine-core/src/lib.rs:100`) is
       the obvious place, but this document does not choose. It is named here
       as a consumer.

**Who decides a rewind.** Ingest decides, not sync (CS-F5). Sync never
emits `Rewind`; it offers blocks, and the alt tier switches.

**Wargame.**
- **Termination.**
  - Every request completes, times out, or its session closes.
  - Each closure removes a session.
  - A run either reaches PoW, is dropped, or fills its budget.
  - `T` grows only with verified PoW.
  - `H*` changes only on more work.
  - So the walk to `L = H*` terminates unless no session can serve,
    which is surfaced as stalled (rule 82), not looped on.
- **Tiny network.**
  - A lone genesis node has `NoView`, so it is not `Synced` and does not
    mine.
  - Mining alone is the operator's declaration (`clearnet = off` and
    `tor = off`, or a closed network through `p2p-closed-peer`): local
    configuration, which the exception audit accepts.
  - This keeps today's behaviour without the latch: the C++ also needs a
    peer to mark synced.
- **Large network.** `T` holds headers only, about 150-200 B each (CS-F6),
  so a full header chain is held in memory. Runs add one byte budget per
  session.
- **What an attacker can do with `NoView` and `Behind`.** Nothing. Both
  are derived from verified work, except `NoView`, which only withholds
  `Synced`.

---

## CS-Q3. The wire

**Problem.**
- `RESPONSE_CHAIN_ENTRY` returns up to 10,000 bare hashes
  (`BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT`, `cryptonote_config.h:97`),
  which carry no proof of work. So a peer can make us reserve spans for
  junk.
- It also carries fields no receiver reads: `first_block`,
  `m_block_weights`, `cumulative_difficulty`.
- Messages that need no flag still carry one:
  - `prune` is set to false everywhere, yet the responder still honours
    it (FOLLOWUPS:244).
  - `missed_ids` has no reader.
- `RESPONSE_GET_OBJECTS` has no byte budget (FOLLOWUPS:1101). Its
  ingress cap is the 100 MB packet.
- Once DRS-SB discard lands, peers will hold no prunable bytes below the
  discard frontier. So full-body sync from genesis stops being possible,
  and the skeleton wire (F28, which needs `pqc_auth_hash` and the
  archival length) is owed by someone.

**Question.** Keep the four messages as they are, or redesign them while
the wire can still change?

**Ruled (Rick, 2026-10-18): redesign, with three changes, and F28 taken in.**

1. **Headers response.** It carries `pow_blob`s from the fork point,
   bounded by a byte budget, not a count.
   - The ids are derived (`identity_of_pow_blob`); nothing restates them.
   - It carries one claim: the responder's tip work.
   - It says whether more headers follow, which is what lets the step-3
     work test run at the end of a run.
   - Delete `first_block`, `m_block_weights`, `start_height` and
     `total_height`. A height is the index along the chain.
2. **Objects request and response.**
   - The request names hashes, as now.
   - The responder stops at a byte budget and says which hashes it did
     not send. A partial answer is legal **only when the response stopped
     at its byte budget**. A response under the budget must carry every
     requested body inside the responder's advertised verified frontier
     (CS-Q4, the withholding rule).
   - `missed_ids` becomes that explicit not-sent list, which is how
     withholding becomes visible.
   - `prune` is deleted.
3. **The body's form is a function of height, not a request flag.**
   - Discard is uniform across all daemons (PDM).
   - So a block below the discard frontier is served as a skeleton:
     - the unprunable part;
     - `prunable_hash`;
     - `pqc_auth_hash`;
     - the archival length.
   - Above the frontier it is served full.
   - The receiver checks the form against the same rule, so a full body
     below the frontier, or a skeleton above it, is a violation.
   - This takes **F28 into this slice**: the `PDM-Q-F28` row
     (FOLLOWUPS:1408) is owned by CS.
4. **Encoding.** Keep Levin portable storage for these messages. A move
   to canonical binary is a P2P-wide decision, not this slice's.

Commands get new ids and the old ones are retired. The testnet upgrades
all at once, so there is no mixed-version arm.

**Allocation bound.** What a malicious peer can make us hold:
- `T`: headers PoW-verified one at a time;
- one run budget per session, plus at most one long run up to the size of `T` (CS-Q2 step 3);
- one byte budget per outstanding objects request;
- the ingest window.

All four are fixed by our own constants, not by what peers claim. The
~200 MB log amplifier (`.inl:97-103`) is already closed by
`describe_peer_blob`; the Rust port keeps digest-not-bytes.

**Wargame.**
- **Junk hashes.** Gone: there are no unproven ids on the wire.
- **Inflated tip claim.** It costs the liar its session at the end of
  its own run, with zero hashes.
- **Partial or withheld bodies.** Explicit and attributable to that
  session.
- **Tiny network.** No change.
- **Budget values.** `Assumption`s until measured on the Rust path
  (Ruling B, CS-Q11).

---

## CS-Q4. Adversarial sync, and what closes a session

**Problem.** The C++ gives a peer's failures assorted, ad-hoc
treatments:
- drop the connection, with a score or without;
- flush spans;
- "drop all connections from this host".

There is no model of which failures are attributable to the peer.

**Question.** For each attack, what does Rust sync do?

**The ruled principle this sits under: PWD-B7** (`SHEKYL_P2P_PROTOCOL.md`
§PWD-B7, RULED; landed as `rust/shekyl-peer-policy`):

> Drop the peer only when the rejection is *attributable to the sender's
> choice*. That requires two things together — the rejection must describe
> the INPUT rather than our own state, *and* the rule it fails must be
> UNIVERSAL rather than local policy.

PWD-B7's sites are transaction rejections. It does not rule on timeouts,
slow peers or withholding. Each arm below is tested against its principle,
not against a ruling it never made.

**Ruled (Rick, 2026-10-18).** One rule:

> A session is closed, with a typed cause, when its peer sends input that
> fails a universal rule: bytes that fail verification, or a response that
> breaks the wire's own obligations. Missing a deadline reassigns the
> work. It does not close the session.

Nothing persists beyond the close (CS-Q5). The three candidate arms,
tested against PWD-B7:
- **Bytes that fail verification:** input, universal (consensus and the
  wire). This arm is consistent with PWD-B7, and it is the droppable
  class PWD-B7 names.
- **Withholding** is attributable only if the wire makes it a universal
  rule. CS-Q3.2 does, under one condition stated here:
  - an objects response that stops **under** its byte budget must carry
    every requested body inside the peer's advertised verified frontier,
    in the form its height dictates (CS-Q3.3);
  - a hash left out of an under-budget response is a form failure, and
    the session is closed;
  - a response that stops at the budget is legal, and the not-sent tail
    is re-requested.
- **A missed deadline** fails PWD-B7's second conjunct. The deadline is
  derived from our **local** rate floor, an `Assumption`, so it is local
  policy, not a universal rule. A slow honest peer on a thin link, or a
  path attacker delaying packets, would be severed. That is what PWD-B7
  warns of: "a drop rule doing rate limiting's job is what severs honest
  peers". Two options:
  - **(i) Reassign without closing (ruled).** The span goes to
    another session. The slow session stops being a body source for the
    rest of that run, a local scheduling choice, not a drop. It stays a
    relay peer and a header source.
    - What it costs: a slow-drip attacker keeps its slot.
    - Who bounds that: the dialer's composition and PWD-B1's per-peer
      bucket (CS-Q5), not sync.
  - **Not taken: (ii) close on a missed deadline,** which would have
    been a named exception to PWD-B7.

**Where the verdicts live.** The mapping from the entry's reply (CS-Q2
step 6) to a session action is built in `shekyl-peer-policy`, beside
`BlockAnnounceAction` and `BlockSyncAction`. It uses PWD-B7's tri-state
`DropVerdict`, whose unset arm does not sever (CS-Q1). It is additive:
the existing types are extended, not replaced.

| Attack | What happens | Cost to attacker / cost to us |
| --- | --- | --- |
| Eclipse during initial sync | Sync cannot detect a total eclipse; defence is the dialer's uniform draw and `ReleaseAnchors`. Headers-first means that when one honest session appears, its heavier headers win before bodies are connected deep (CS-F3) | — |
| Long low-work fork | Its claim is below `work(H*)`, so it is never asked. A liar claiming more is caught at the end of its run: the run's computed work falls short of the claim | Zero hashes if the work falls short; at most one run budget held. If the headers carry inflated work, the first PoW check fails: at most one hash per session |
| Withholding | A body inside the advertised frontier, left out of a response under its byte budget, is a form failure, and the session is closed. A response stopped at the budget is legal; the tail goes to another session that holds it | Bounded by the sessions holding the span |
| Slow drip | Each request's deadline = the connector's transit (from its declaration, `transit_ms`) plus bytes asked over a rate floor. Late means the span is reassigned and the session stops being a body source for that run. It is **not** closed, under option (i) above (PWD-B7) | The rate floor is an `Assumption` until measured. The slot it keeps is bounded by the dialer and PWD-B1, not sync |
| Body passes framing, fails `validate` | The header's PoW is on the selected chain, so the attacker mined it at honest difficulty; subtree invalidated, session closed | Attacker: one real block's mining. Us: one block's validation |
| Invalid-PoW announce | The cheap checks run first (parent known, timestamps, difficulty); then PoW; a failure closes the session | One RandomX hash per announce that passes the cheap checks, and one session spent by the attacker. Unsolicited work is capped (CS-Q5) |
| Cost asymmetry on a Pi 4 | Every expensive check is gated on PoW the attacker paid for at selected-chain difficulty; the checks that need no store run in parallel in `form` (Rick's 2026-10-16 ruling, #1082) | Not estimated here; measured in CS-Q11 |

**The D_max trap (CS-F3) is a decision on its own.**
- It is consensus's cap, not sync's to change.
- Options:
  - (a) Accept it, surfaced: raise the `Diverged { fork_at }` alarm, a
    rule-82 failure that is loud and persistent. RPC shows it, and the
    wallet's sync view carries it (CS-Q2 step 7). The remedy is the
    operator's (a resync).
    - It is an **alarm only**. It does not withhold `Synced`, and the
      miner and the relay gate keep running on our chain.
    - **Why not withhold `Synced`:** anyone who outworked the network
      for `D_max` blocks could then halt honest mining everywhere just by
      showing headers, which is a remote halt.
    - An honest node cannot tell "I was eclipsed" from "they attacked".
      Refusing that reorg is the cap's purpose, and stopping the miner
      would hand the attacker a second win.
  - (b) Let `D_max` not bind during initial sync. That is a special
    case, and a remote party benefits: an eclipser's chain is exactly
    what sits there.
  - (c) Make the window small instead: headers-first collects headers
    from every session before committing bodies past the deepest point
    any session disputes.
    - **When the wait starts.** It starts when the body scheduler is
      about to commit the first span past a fork point that some
      session's claim disputes, meaning a session whose claim exceeds
      `work(L)` and whose run has not ended. The sessions established
      at that moment form the set the wait covers.
    - **The wait is bounded.** It ends when every session in that set
      has finished its run (step 3) or missed its request deadline.
      That deadline is the connector's declared transit plus the bytes
      over a rate floor, an `Assumption` until measured.
    - Sessions established after the wait starts are not waited for. A
      heavier chain they bring within `D_max` reorganizes normally.
    - If no session holds `H*`'s bodies, that is a stall: surfaced, not
      waited on.
- **Ruled (Rick, 2026-10-18): (a), with (c) as the normal behaviour.** Headers-first
  makes the trap need a total eclipse, then a heavier chain appearing
  after more than `D_max` blocks.
- **Tiny network.** Two halves of a testnet that mine apart for more than
  24 h never rejoin. That is `D_max`'s design. (a) makes it visible
  instead of silent, and both halves keep mining.

**Wargame for the closing rule.**
- **Who can trigger a close.** Only the peer, of its own session, by
  sending input that fails a universal rule.
- **The exception: on clearnet an active MITM can forge any failure,
  because NN is unauthenticated.** What that buys it:
  - The close of a session it already controls.
  - No forgetting, no ban, no score. The dialer redraws uniformly, and
    it may redraw the same address.
  - This is the R2 reasoning applied to sync.
- **Termination.** Every close removes one session; the dialer's fill
  is the only path back.

---

## CS-Q5. Scoring: rebuild `add_host_fail` in Rust, or delete it?

**Problem.**
- Today `add_host_fail` (`net_node.inl:349`) adds weights (1, 5, 10)
  into an un-decaying per-host map. At more than
  `P2P_IP_FAILS_BEFORE_BLOCK` (10, `cryptonote_config.h:200`) it bans the
  host for 24 h through the transport ban list.
- It is fed from:
  - this handler (`:2570`, `:2615`), with the weight picked by
    `shekyl-peer-policy`'s `heavier_score` predicate:
    `P2P_IP_FAILS_BEFORE_BLOCK` or 1 (`.inl:649`, `:1512`);
  - slice 4's inbound handshake (`net_node.inl:941`, `:949`);
  - the outbound timed-sync peerlist refusal (`net_node.inl:582`).
- The dialer brief routed `PeerlistRefused` to "the score owner"
  (`P2P_3_SLICE_3_DIALER_BRIEF.md:504`).

**Question.** Does Shekyl keep an automated, persistent per-host
misbehaviour score, and if so, who owns it?

**Options.**
- **(a) Port it** as a Rust score owner that subscribes to the outcomes.
- **(b) Redesign it** with decay and attribution classes.
- **(c) Delete automated scoring.** Misbehaviour closes the session with
  a typed cause (CS-Q4). Bans stay operator configuration only (the RPC
  `set_bans`, the transport `BanList`).

**Ruled (Rick, 2026-10-18): (c).**

What a persistent ban is *for*: making a host that has proven malicious
stop costing us resources. Against Shekyl's actual inputs, it buys
nothing:
- **Clearnet misbehaviour is not attributable to an IP.** NN is
  unauthenticated, so an active MITM can forge any failure. A ban then
  forgets an honest host for 24 h, which is the R2 harm ("forgetting
  shrinks the dial set, favours whoever feeds us addresses").
- **Onions are authenticated but cannot be banned** (D7).
- **IPv6 addresses and onions are equally free** (Rick's 2026-09-30
  ruling), so a per-address ban does not stop a determined sender.
- **What does bound the cost** is protocol ordering (cheap checks before
  PoW, one outstanding request per session, byte budgets) and the
  transport's inbound ceiling (`admission.rs`). Those hold whatever the
  address.

**The bound that remains, and who owns it.**
- Today nothing limits how fast inbound sessions turn over. An attacker
  can close and reopen sessions, and each new session can cost us one
  RandomX hash for an unsolicited announce.
- A ban would not change this, since the addresses are free, so it does
  not argue for (a) or (b).
- The answer has two parts:
  - **In this slice: solicited work comes first.**
    - Header and body verification for responses *we requested* draw
      from the shared hasher budget ahead of unsolicited announces.
    - Unsolicited announces get a capped share. Beyond the cap they are
      dropped unverified.
    - The key is "we asked", not the session's direction, so the rule
      is the same on inbound and outbound sessions.
    - A remote party cannot make its work solicited, because we choose
      what to request.
    - Dropping an honest announce is safe. The next announce's
      `Unlinked` reply, or a hint from another session, starts a
      solicited sync.
    - So an inbound flood can delay how fast we learn a new tip, but it
      cannot stall a sync in progress.
    - The cap's value is an `Assumption`.
  - **Outside this slice: the registered clearnet reconnect throttle.**
    - `P2P_TRANSPORT_LAYER.md`, "Clearnet reconnect throttle —
      REGISTERED 2026-10-09, not built" (D-S1).
    - It refuses a host's new inbound handshakes for a cooldown after
      `N` completed handshakes within `T`. It throttles only: no score,
      no ban.
    - The IPv6 key is a prefix (Rick's 2026-10-11 ruling). `N`, `T` and
      the prefix length are measured on the Rust transport after the
      cutover.
    - Its Tor residual: an onion peer's reconnect is bounded only by
      D-S1's per-session cap and Tor's rendezvous PoW.
    - **What this means for sync.** An invalid-PoW announce closes its
      session (CS-Q4). So each starved slot in the unsolicited share
      costs the attacker one reconnect, and the throttle prices that
      reconnect on clearnet.
    - Until the throttle is built, the residual is an inbound flood
      that delays tip learning, bounded by the unsolicited share.
  - **Outside this slice: PWD-B1's per-peer token bucket** (RULED, NOT
    IMPLEMENTED; `SHEKYL_P2P_PROTOCOL.md` §PWD-B1, FOLLOWUPS:1120,
    "Extend PWD-B1's bucket to *every* dispatch").
    - Its surface is every dispatch, including the nine
      `HANDLE_NOTIFY_T2` routes in this handler
      (`cryptonote_protocol_handler.h:94-102`).
    - The rate of one session's unsolicited announces is B1's. The
      share those announces get of the hasher is CS's. They compose,
      and neither stands in for the other.
    - **The CS cutover adds new dispatch routes** (CS-Q3). They fall
      inside B1's ruled surface.
    - **Ruled:** CS's routes carry B1's charge point, a call ahead of
      every handler. B1's four parameters, and the bucket itself, stay
      B1's owner's.
    - If B1's bucket has not landed by the CS cutover, the charge point
      is the one place it attaches. That is not a second mechanism.
    - **Not taken:** B1 adding the charge to CS's routes when it lands.
  - **Not taken: priority for dialer-drawn outbound sessions.** Keying on
    solicitation gives the same protection without a rule keyed on
    direction.

**What goes:**
- `add_host_fail` and `m_host_fails_score`;
- `P2P_IP_FAILS_BEFORE_BLOCK`;
- `hit_score` and `m_score`;
- the dialer brief's "score owner" sentence;
- **landed Rust (ruled with the rest):** the `heavier_score` arm of
  `BlockAnnounceAction` and `BlockSyncAction`
  (`shekyl-peer-policy/src/block_peer.rs:103`, `:175`), and its two FFI
  predicates (`peer_policy_ffi.rs:257`, `:292`).
  - This arm exists only to pick a score weight.
  - The rest of the crate stays and is extended (CS-Q1, CS-Q4).

Slice 4's two inbound calls go with slice 4's port. The test overrides
go too: `tests/unit_tests/node_server.cpp:591` and
`sync_orphan_arm.cpp:145`.

**What stays:** operator bans and their expiry, and the registered
reconnect throttle, which is not a ban.

It is cut at the CS cutover, with the sync half; slice 4's calls go with
slice 4.

**Wargame.**
- **Invalid-PoW spam from rotating IPv6 addresses.**
  - It costs one hash per announce, and the attacker one session per
    announce.
  - It is bounded by the unsolicited share of the hasher budget, a
    property this design adds; the C++ has no such bound.
  - Once the throttle is built, it is also priced per IPv6 prefix.
  - A ban would not change it.
- **Valid-PoW invalid blocks.** The attacker mines at network
  difficulty. Self-limiting.
- **Tiny network.** Nothing changes. Scoring never helped a network of
  three.

---

## CS-Q6. Tor

**Problem.**
- The C++ refusal is gone (`aebe4c5cc`, 2026-10-01), and Rick's 2026-09-30
  ruling makes a Tor-only node first-class.
- What is left is the privacy cost, and the timing.

**Question.** What does syncing over Tor expose, and does any of it need
a mechanism?

**What is exposed, by property.**
- **To a peer, while we are behind:** our tip.
  - The locator names it, and the handshake payload claims it.
  - A tip that lags is a rare value. So a peer that sees us over both
    clearnet and Tor can link the two sessions while we catch up.
  - At the tip, every node shows the same value, so there is no
    linkage.
  - Removing the handshake payload would not close this: the locator
    must name our chain to find the fork point.
- **To a peer: the request volume and pattern of a bulk download.** These
  are the same for every node, carry no wallet information, and reveal
  only "this node is catching up".
- **To a local observer of our Tor guard:** volume and timing. That is
  TRC-1's domain (relay cover), not this slice's.

**Ruled (Rick, 2026-10-18).**
- No sync mechanism keyed on the connector.
- Record the lag-window linkage as a named, accepted property:
  - adversary: a peer present on both networks;
  - what is exposed: our tip while behind;
  - window: until `Synced`.
- Request deadlines read the connector's declared transit (CS-Q4), which
  is data and needs no Tor branch. The Tor gap is 37.4 s, `RustPath`
  (`BENCHMARK_ALIGNMENT.md:352`).
- The round doc's §6 carries this ruling.

**Wargame.**
- Linking our onion to our IP during catch-up needs the adversary in
  both peer sets. Their benefit is posture inference, not funds or
  transaction origin. D++ origin protection rides other edges.
- If the window is to be closed, the one mechanism that does it is "a
  node behind on both connectors syncs over one". That is a connector
  branch and a special case, so it is not taken.

---

## CS-Q7. Peer demand

**Problem.**
- The C++ had two levers that shaped outbound composition from sync
  (CS-F4).
- PR-3's rule is that peers come from the dialer, and there must be no
  second dial path.

**Question.** How does sync's need for peers reach the dialer?

**Ruled (Rick, 2026-10-18): it doesn't, because sync needs no demand channel.**
- Sync downloads from every established session, inbound and outbound.
  The data's trust comes from PoW and validation, not from who sent it.
- Sync closes a session only when its peer fails an obligation (CS-Q4).
- A close lowers the dialer's `Keep` count, and the dialer's ordinary
  fill (rule (b)) redraws uniformly.
- So "I need better peers" is expressed as data the dialer already
  reads: the count of kept sessions.

**What is deleted:**
- `update_sync_search`;
- `needs_new_sync_connections`;
- `P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT` (`cryptonote_config.h:197`);
- **landed Rust:** `rust/shekyl-ffi/src/sync_ffi.rs`
  whole, meaning `shekyl_sync_room_for_syncing_peer`,
  `shekyl_sync_wants_more_outbound`, `SYNC_SEARCH_CONNECTIONS = 2` and
  its tests.
  - Its only consumers are the two C++ functions above. It moved their
    comparisons into Rust without ruling on the levers themselves.

Both halves, the C++ and the landed Rust, are deleted at the CS cutover.
The Rust half was raised on its own and ruled with the C++.

**Wargame.**
- **What it buys an attacker.** It cannot make us close an honest session
  except by MITM (CS-Q4). What that gets it: one uniform redraw.
- **A peer that is merely behind** is not closed. It is a fine relay
  peer.
- **Being behind with no session holding `H*`'s bodies** is surfaced as
  stalled, not looped on.
- **Tiny network.** Peers that are all equal close nothing.
- **What `update_sync_search` was for.** Exploring for other chains while
  synced. The dialer's confirm dials and churn already bring new tips:
  a kept honest session's announce is enough to learn a heavier chain.

---

## CS-Q8. Concurrency

**Problem.**
- Sync runs on whichever strand holds `m_sync_lock`, on the 2-worker I/O
  pool, and it is driven by three polls (8 s, 100 ms, 101 s).

**Question.** Where does Rust sync run, how much is in flight, and how
does it meet ingest's backpressure?

**Ruled (Rick, 2026-10-18): as written.**
- **One sync owner task,** on its own runtime row in the thread ledger,
  like the dialer's owner.
  - It owns all sync state: `T`, `H*`, the runs and the per-session sync
    state. Sync state stays out of `Connection`, which keeps `m_state`'s
    session-lifecycle job on the seam (CS-F7, "one mechanism, one
    job").
  - Sessions deliver decoded sync messages to it as events.
  - Deadlines are timing-engine owners, so nothing polls.
- **In flight:**
  - one request per session;
  - bodies capped by a global byte budget;
  - headers capped by a per-response byte budget, and unverified headers
    by the per-session run budget, with at most one long run at a time.
- **Header PoW** runs on the same bounded hasher budget as ingest's
  `form` workers (DX-Q2 item 6, landed in #1101). So headers and bodies never
  together exceed the RandomX scratchpads a Pi 4 can hold. Solicited
  work comes before unsolicited work within that budget (CS-Q5).
- **Backpressure.** Sync requests bodies only when the entry reports
  room. A requested body is never dropped for lack of room.

**Wargame.**
- **Termination.** Every wait is a deadline or an event.
- **Tiny and large networks.** One owner scales with sessions; the
  budgets are ours.
- **Attacker trigger.** None, beyond the per-session bounds above.

---

## CS-Q9. The deletion table and the freeze

**Problem.** The handler files are not frozen. `dial_path_freeze.tsv`'s
only `cryptonote_protocol` row is `levin_notify.cpp`. DRS-X's flip will
edit `try_add_next_blocks` to call its entry.

**Question.** Should these files join `scripts/ci/dial_path_freeze.tsv`
as shrink-only rows now?

**Ruled (Rick, 2026-10-18): yes.** Add shrink rows for:
- `cryptonote_protocol_handler.{inl,h}`;
- `cryptonote_protocol_handler-base.cpp` and `_common.h`;
- `block_queue.{h,cpp}`;
- `cryptonote_protocol_defs.h`.

Two DRS-X PRs edit the handler before the CS cutover, and each carries
its own `UNFREEZE` line:
- **DRS-X PR 2:** "Until the chain-sync cutover the C++ handler's span
  scheduler asks once per span" (`DRS_X_STORE_FLIP.md:63`). That is the
  room check before each span.
- **The flip:** `try_add_next_blocks` calls the entry.

That is the existing mechanism, and Rick's 2026-10-15 correction allows a
C++ seam.

The flip is gated on DEL-008 (CS-Q10), so the C++ handler lives on for a
while under these rows.

`cryptonote_protocol_handler.{inl,h}` are rows that are expected to
**shrink**, not to disappear, at the CS cutover, because the CS-Q1 ruling
keeps the transaction routes in the same invoke map as RD's (CS-Q10). A
shrink row retires only when its file is deleted. That happens at RD's
cutover or at CS's, whichever lands second.

The function-by-function `rg` before and after (rule 47, `rg -n -e` only)
goes in the brief, one row per CS-Q1 line. The cutover's gate is that
every pattern in the table returns nothing.

**Wargame.** A shrink row cannot block a deletion. It only makes an
addition visible.

---

## CS-Q10. Sequencing

**Problem.** This slice depends on four other pieces of work:
- PR-3, which has landed;
- slice 4, unbuilt;
- RD, unbuilt;
- the DRS-X entry, ruled in Round 0 (#1101). PR-b, the pool door, has
  merged (#1102); PR 2, which builds the entry, is "briefed after PR-b's
  door lands" (`DRS_X_STORE_FLIP.md:286`).

**Question.** What can start now, and does the cutover land whole or in
increments?

**Ruled (Rick, 2026-10-18): as written.**
- **Now, pure Rust, no FFI:**
  - (1) the header-chain verifier (over `shekyl-difficulty`, RandomX and
    `ReleaseAnchors`), tested against the captured chains;
  - (2) the sync model as a crate with property tests (CS-Q11);
  - (3) the new payload types in `shekyl-levin` with KATs.
- **The cutover's horizon.** The cutover follows the DRS-X flip. The flip
  needs PR-b, PR 2, PR 3, PR 3b and #1088; PR-b and #1088 have merged
  (`DRS_X_STORE_FLIP.md:154`). Its archival deletion waits on DEL-008's
  gate (`:144`, `:260`):
  - Slice C's admission rows `implemented`;
  - CEN-J8–J10 retired;
  - the secret draw live.

  So the CS cutover is the far end of this work. What starts now (above)
  stands, and the freeze rows (CS-Q9) carry the C++ until then.
- **The cutover is one PR, after the DRS-X flip.** It does three things
  at once:
  - delete the **sync half** of the handler and `block_queue`;
  - start the sync owner;
  - change the wire.
- **Only the sync half,** because the transaction routes in the same
  `BEGIN_INVOKE_MAP2` are RD's under CS-Q1: `handle_notify_new_transactions`,
  `relay_transactions` and complement serving
  (`handle_notify_get_txpool_complement`).
  - **`DRS_X_STORE_FLIP.md` says the opposite.** `DRS_X_STORE_FLIP.md` §4
    item 6 (`:290`): "Chain sync's cutover follows the flip and deletes
    the shell's protocol-handler half. **RD** deletes `levin_notify` and
    the relay entry." That gives the handler's transaction routes to CS.
    It is §A's coupling 1, settled by the CS-Q1 ruling, and needs a docs
    PR against that text.
  - If RD has not landed by the CS cutover, a shrunken C++ handler
    survives holding only those routes.
  - **The complement request moves to the sync owner.**
    - Today, `on_connection_synchronized` (`.inl:2240`) fires
      `request_txpool_complement` once, when sync completes, guarded by
      a `compare_exchange` ("One ask", `.inl:2289-2305`). CS deletes
      that function.
    - After the cutover, the sync owner sends its own Levin requests
      from Rust, and the pool is Rust (#1102). So the request is the
      sync owner's own send, at its own transition to `Synced`.
    - The reply is `NOTIFY_NEW_TRANSACTIONS`. It goes through RD's
      route, C++ or Rust at the time, into the Rust pool.
    - Serving a peer's complement request
      (`handle_notify_get_txpool_complement`) stays RD's.
    - No callback, and no new C++. Until the cutover, the C++ trigger
      stays as it is.
  - Whichever of RD and CS lands second deletes the file.

  Increments that wired the C++ handler into Rust only to delete it a
  PR later are joined, as in the PR-3 precedent.
- **Slice 4.** Until it lands, its C++ inbound paths call the sync
  owner's hint intake through one FFI entry. That is the same shape the
  dialer's result already uses, and slice 4 deletes the caller.
- **RD.** Independent. It reacts to `Synced` and owns transactions.

**Wargame.** Nothing here is remotely triggerable. The risk is a
half-cut, and one cutover PR avoids it.

---

## CS-Q11. Tests and measurement

**Question.** What is the reference, and what is measured?

**Ruled (Rick, 2026-10-18): as written.**
- **Property tests against the model (CS-Q2), not against the C++:**
  - `H*` is always the most verified work among reachable chains;
  - no body is requested off `H*`;
  - every request ends;
  - no RandomX hash is spent on a run whose computed work does not
    exceed `work(H*)`;
  - an honest chain longer than one response is never refused;
  - a refusal invalidates exactly its subtree;
  - `PayloadRefused` fires only on structurally impossible claims;
  - `NoView`, `Behind` and `Synced` are derived, never latched;
  - a claim's value never changes the sync state;
  - only a run in the long slot, or one taking it, pays PoW before it
    exceeds `work(H*)`; the slot goes to the most verified work at equal
    height;
  - the `Diverged` alarm latches until a resync and sets
    `following_degraded`;
  - `Diverged` never withholds `Synced`;
  - a missed deadline reassigns the span and never closes the session;
  - a body left out of an under-budget objects response closes the
    session.
- **Adversarial harness.** Scripted peers over real Levin framing on
  loopback (`shekyl-p2p-harness`): honest, liar, withholder, slow-drip,
  low-work fork, invalid body, and an unsolicited-announce flood during
  a solicited sync.
  - They drive the real sync owner against a real store and real ingest,
    using `chain-ingest`'s captured chains.
  - That is a production pathway with adversarial peers, not mocks.
- **Regtest.** Multi-node, including a partition held for more than
  `D_max` blocks. It must end with the `Diverged` alarm raised on both
  halves, and both halves still mining.
- **Pi 4, after the cutover, each figure labelled `RustPath`:**
  - headers per second and bodies per second, over clearnet and over
    Tor;
  - peak memory;
  - writer idle %;
  - per-request transit by connector.

  These figures set the byte budgets, the run budget, the rate floor,
  the unsolicited share and the deadlines, which are `Assumption`s until
  then. They also discharge FOLLOWUPS:1126 (the initial-sync cost at
  the floor) and :1101 (the response byte budget).

---

## CS-Q12. The four lane-owned sync options

**Problem.**
- The input grammar hands four daemon options to this lane:
  `prep-blocks-threads`, `block-sync-size`, `span-limit` and
  `block-download-max-size` (`INPUT_GRAMMAR.md:270`, legend **L**,
  "lane-owned (not ported; IG-Q4)").
- The daemon no longer reads them. Today's defaults are hardcoded "until
  that lane decides":
  - the handler's `init`: `m_block_download_max_size = 0`,
    `m_span_time = 2` (`.inl:248-251`);
  - `cryptonote_core.cpp:304-311`: `blocks_threads = 4`
    (`prep-blocks-threads`);
  - `cryptonote_core.cpp:414-415`: `block_sync_size = 0`, adaptive
    through `get_block_sync_size` (`:608`) over
    `BLOCKS_SYNCHRONIZING_DEFAULT_COUNT` (20, `cryptonote_config.h:100`).

**Question.** Does any of the four survive as an operator option?

**Ruled (Rick, 2026-10-18): none survives.** Each becomes an **X** row, refused
with its reason, under IG's REJECTED convention:
- **`span-limit`, `block-sync-size` and `block-download-max-size`** are
  replaced by protocol constants: the per-response, objects and global
  byte budgets, and the deadlines (CS-Q2, CS-Q3, CS-Q8).
  - They are provisioned at the floor device (rule 76) and measured on
    the Rust path (CS-Q11).
  - An operator setting would only let a node mis-provision itself
    against the floor.
  - Metered links are IG-Q40's reopening (a byte quota). The link budget
    is already `p2p-download-max`.
- **`prep-blocks-threads`** is the shared hasher budget's (DRS-X DX-Q2
  item 6, CS-Q8). That budget is derived from what the floor device's
  scratchpads hold, not chosen by the operator.
- The hardcoded values die at the cutover: the handler's two with
  the sync half, and the core's two with what replaces their callers.
  Until then they stand as today's defaults.

**Wargame.**
- **Remote trigger.** None: these are local options.
- **What refusing them costs.** An operator who tuned spans has nothing
  to tune. The budgets are ours, sized at the floor, which is rule 76's
  point.

---

## §A. What chain sync needs from the DRS-X entry

DRS-X adopted these in #1101, landed (DX-Q2 items 2, 3, 5 and 6,
`DRS_X_STORE_FLIP.md:58-73`). They are kept here as the requirement that
document says it carries.

1. **One reply per arrival, tagged with the arrival.** The variants:
   `Connected`, `Refused(verdict)`, `Unlinked{at}`, `AlreadyHeld`,
   `Held`, `BeyondCap`, `NoRoom`, and the switch outcomes.
   - `Source` is a pull trait with no path back, so it cannot carry
     this.
2. **Capacity.** The entry reports room before sync requests bodies. An
   accepted arrival is never dropped.
3. **A shared hasher budget,** so that header PoW (sync) and `form`
   (ingest) share the RandomX scratchpads. Sync orders its own share,
   solicited work first (CS-Q5).
4. **Tip publication.** `shekyl_core_publish_tip` moves from
   `Blockchain` to the connector's commit, after every connect, pop and
   switch, as one source. The dialer and sync both read it.
5. **`BeyondCap` reaches sync** as a reply, as the secondary source of
   the `Diverged` alarm on the announce path (CS-Q2 step 7).
6. **A doc fix:** `source.rs:28` and `:43` (CS-F5). DRS-X assigned it to
   its PR 2.

**Each coupling below is a docs PR against `DRS_X_STORE_FLIP.md`,**
relayed to the DRS-X lane.

1. **§4 item 6, the order of work (`:290`),** has chain sync delete the
   whole protocol-handler half of the shell. Under CS-Q1, the
   transaction routes in that handler are RD's.
   - Wording: "Chain sync's cutover deletes the protocol handler's sync
     half, the complement request included. RD deletes its transaction
     routes, complement serving, `levin_notify` and the relay entry.
     Whichever lands second deletes the handler file."
2. **DX-Q2 item 4 (`:64`)** says "Only `Refused(InvalidBlock)` is about
   the peer… never punish". Under CS-Q5 (c) the wording becomes: "`Refused(InvalidBlock)` is the only outcome that closes the
   serving session (PWD-B7); nothing scores".
3. **The carried requirement.** DRS-X says "chain sync's Round 0
   requirement, ruled 2026-10, carried here" (`:60`, `:73`).
   - Ruled 2026-10-18, with §A as written, so the carried text stands.
   - `:292` cites "chain sync CS-F5"; the family is registered with this
     document.
   - The carried text can name this document now: chain sync is row
     **CS** of the §4.2 register, beside **TE** and **RD**, not a
     numbered slice.
4. **`following_degraded` loses its producer at the flip.**
   - The flip deletes `Blockchain` (DEL-010, `:143`), which holds
     `m_following_degraded` and sets it (`blockchain.cpp:2288`).
   - `DRS_X_STORE_FLIP.md` has no mention of `following_degraded`. Yet
     the field is landed RPC (3.26), and the wallet engine reads it
     (CS-Q2 step 7).
   - **Ruled: a Rust-held latch, not shell state.** After the flip the
     switch is Rust ingest's, and its results already carry the two
     refusals: `Switched::BelowFloor` (the undo floor) and `BeyondCap`
     (`D_max`) (`switch.rs:336-340`). Ingest sets the latch from them.
     The sync owner also sets it from the CS cutover (CS-Q2).
   - The RPC reads it in Rust (`info_facts.rs:88`, DX-Q3, #1106). The
     latch semantics are C2-R1b's: one-way until a resync.
   - Without this, the flip silently retires a field the wallet acts
     on. Rule 82 puts that in scope.
5. **DRS-X PR 2 edits the C++ handler** ("asks once per span",
   `:63`). It needs its own `UNFREEZE` line under CS-Q9's rows, if those
   rows land first.
6. **`NoRoom`** is in CS-Q2's verdicts and in §A.1. #1101 names it
   (DX-Q2 item 3, `:62`), so this coupling only needs the two to stay in
   step.

---

## What follows the ruling

**Landed with the ruling:**
- the round doc's §4.2 register has row **CS**, and its §6 carries
  CS-Q6;
- the `PDM-Q-F28` FOLLOWUPS row is owned by CS (CS-Q3);
- the index rows read ruled.

**Relayed:**
- §A couplings 1, 2, 4 and 5 go to the DRS-X lane, as a docs PR against
  `DRS_X_STORE_FLIP.md`;
- the `INPUT_GRAMMAR.md:270` row moves from **L** to **X** with CS-Q12's
  reason. That is the grammar lane's table.

**Next:** the implementing agent's instructions, one consolidated brief,
starting with CS-Q10's pure-Rust work.
