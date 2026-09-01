# P2P-1 — the P2P wire census

**Status:** OPEN — the single live enumeration of Shekyl's peer-to-peer wire
surface and its behavioral commitments. Produced as the P2P-1 artifact the
[P2P-2 requirements register](P2P_2_REQUIREMENTS_REGISTER.md) sequences ahead
of the P2P-2 dispatch brief, and it absorbs that register's §7 open
verification tasks as census work rather than deferring them again. This is
the specification input for the P2P transport/protocol redesign; the inherited
C++ is a differential-test oracle only for rules this census marks ratified.
Bucket-4 rows record questions, never answers.

**Decision authority:** the census enumerates; it does not rule. Where a row
reads as a disposition ("delete this", "adopt that"), it is recording a
*candidate* and naming the rule that would authorise it — the ruling itself
belongs to P2P-2 or to the owning lane. This document changes no code.

**Pinned sha:** `30cd547e2e9146bd30d7313e644246a9794b57d3` (`dev` tip,
verified against `git ls-remote origin` at 2026-09-01T15:13Z). Every
`file:line` below was read at this sha.

The pin is **at or after** three merges that moved this exact surface after
the register was written, which is why the register's own pointers are
re-located rather than trusted:

| Merge | What moved | Effect on the register's pointers |
| --- | --- | --- |
| #587 (`cf3b13c29`) | `rpc_port` + `rpc_credits_per_hash` deleted from `basic_node_data` and every peerlist entry; peerlist store `6 → 7`; `BOOST_CLASS_VERSION(peerlist_entry) 3 → 4` | PW-14's `rpc_port` half is **gone at the tree** — see PWC-D7 |
| RK-5a (`d468625e0`) | `cryptonote::connection_info` and `t_cryptonote_protocol_handler::get_connections()` deleted | shifted every `cryptonote_protocol_handler.inl` line number the register cites — see PWC-E9 |
| #580 (`63d543103`) | carrier producer; `levin_notify.cpp` reworked, `i_core_events::pool_has_tx` added | the D++ emit path is Rust-owned; bounds this census's `levin_notify` decision (§2.3) |

**Identifier family:** `PWC-` (P2P wire census), form
`PWC-<letter><n>[letter]` following the registered `CEN-<letter><n>[letter]`
precedent. Uniqueness checked mechanically against every prefix in the index's
§2 table under the alphabetic-until-digit rule — `Bond- CB- CEN- census- CR-
CT- CT-ACT- CW- DQ- DRS- DS- F- GF- LV- M3a– MR- MS- MSW- OA- P- PC- PD- PR-
PW- Q12- RC- RF- RK- RP- RT- S- SA-R- SCE- SH- SJ-DQ- SM-DQ- SO- SP- TJ- VG-
WI- WI-RPC- WP- X-` — plus a tree-wide grep for `PWC-` returning zero hits.
`PWC` is distinct from `PW`, `PC`, `PD`, `PR` and `P`. Registered at birth
(rule 94 §1) in this document's landing PR.

**Scope boundary, re-verified at this pin:**
[`RPC_TRANSPORT_POSTURE.md`](RPC_TRANSPORT_POSTURE.md) §2.1 — "The
peer-to-peer layer talks to strangers by construction… RPC is
operator-to-operator; P2P is adversarial by design and hardened separately."
The register cites this at `:99-106`; **at this pin the paragraph is
`:101-107` and the subsection `:99-114`** (one line longer, same anchor line).
RT-4's pinned-mutual-TLS mechanism is not transferable here, per that
register's own framing.

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
this is priority-3 longevity work. A transport redesign cannot take
inherited-but-unexamined C++ as its specification
([`16`](../../.cursor/rules/16-architectural-inheritance.mdc),
[`60`](../../.cursor/rules/60-no-monero-legacy.mdc)); an unlisted rule is
ratified by silence, and this census exists to close that failure mode on the
p2p surface the same way the consensus census closed it on the acceptance
path.

---

## 1. Archaeology leg — what already landed on or beside this surface

Run **before** the wire walk, so the walk reads a surface whose history is
known rather than re-deriving it. Each entry is located at this pin; status is
as the owning doc states it, not as remembered.

| # | Workstream | Where | Status as stated | Bearing on this census |
| --- | --- | --- | --- | --- |
| 1 | **Q12-D6a peer-discovery run** | [`Q12_D6A_PEER_DISCOVERY_RUN.md`](Q12_D6A_PEER_DISCOVERY_RUN.md) `:1-35`; index `:136` | **RUN** — `{15,30,60}` sweep §§13-15 + Q12-R5 late-joiner control, 2026-08-14; §16 closes the distinctness question | Supplies the anti-ruling leg of the no-authentication constraint (`:2910-2917`, `:2979`, `:3013`) and the one-P-per-wallet-on-wire pin (§10.9) |
| 2 | **Q12-U1 / Q12-U2** | [`Q12_FORWARD_DELAY_AND_ZONE_FIELD.md`](Q12_FORWARD_DELAY_AND_ZONE_FIELD.md) `:8`, `:779-780`, as-built `:793+` / `:880+` | **LANDED 2026-08-12, both in PR #459** | **Corrects the dispatch premise.** The brief that opened this census carried them as *open*; they are landed, and U2's landing is visible in the tree at `cryptonote_protocol_handler.inl:885-904`. Recorded as PWC-X1 |
| 3 | **D++ / relay-privacy lane** | [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §6.10 `:1000-1097`, §12.10 `:2480-2542`, §12.11 `:2543-2773` | §12.10/§12.11 designed, **not built**; §12.11 carries two superseding banners (`:2545-2553`, `:2555-2574`) | Owns admission/eviction (PW-23…PW-26). §7 task 1 resolved against it — see §5.1 |
| 4 | **Network-posture proxy wiring (RT-W7)** | [`RPC_TRANSPORT_POSTURE.md`](RPC_TRANSPORT_POSTURE.md) `:561`, `:480-481`; index `:105` | **LANDED 2026-08-23 (PR #542)** | Confirms the RPC-side posture is settled and is *not* this lane's; one loopback predicate (`listen::is_loopback_ip`) for listen and outbound |
| 5 | **RT-lane boundary (§2.1)** | `RPC_TRANSPORT_POSTURE.md:99-114`; RT-9 `:333-373`; RT-W5 `:559` | RT-9 **RULED 2026-08-21**; RT-W5 **LANDED**, UPDATE 2026-08-31 records #587 finishing the P2P half | The scope boundary above, and the ratification PWC-B3/PWC-D7 lean on |
| 6 | **SP-T3 Tor guard-sharing** | [`SP_T3_SKELETON_MEASUREMENT.md`](SP_T3_SKELETON_MEASUREMENT.md) §21.1 `:1483-1515`; SPIKE-F-12 `:80` | SPIKE-F-1 **REFUTED AS STATED**; SPIKE-F-12 **CONFIRMS ACCEPTED RESIDUAL** — guard set is per-process/datadir | One tor process ⇒ one entry-guard set ⇒ a single guard sees every stem successor. Bounds any transport row that would claim Tor restores D++ independence |
| 7 | **P-transport / SP-T serving-loop arc** | `rust/shekyl-p-transport/src/lib.rs:134`; index `:101`, `:178`, `:206` | `derive_socks_user` **still at :134**, unmoved; lane **partially built, inert** (`PTorClient`/`PBlockSource` `dead_code`) | The partial answer PW-22 rests on; §7 task 3 resolved against it — see §5.3 |
| 8 | **E′ transport (MS-5)** | [`V3_1_MULTISIG_RUST_ENGINE.md`](V3_1_MULTISIG_RUST_ENGINE.md) §0.5 `:310-357`, `:989-1060`; index `:125` | Round 1 **CLOSED**; MS-5 **S1 LANDED** | **Surfaced under PW-22 but out of scope here.** Every "transport blob" hit is a multisig file envelope or a consensus blob, not a p2p transport. Recorded as PWC-X2 so the next reader does not re-run the search |
| 9 | **Carrier / cover-traffic** | [`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md) §3.1a `:922-1028`; index `:242` | steps 1-4 landed; **step 5 BLOCKED** on a daemon/p2p cutover; #580 index stamp still says "not on `dev`" | The stamp is now stale — #580 merged as `63d543103`. Recorded as PWC-X3 |
| 10 | **Levin Rust migration (LV-)** | index `:140`; [`LV2_PORTABLE_STORAGE.md`](LV2_PORTABLE_STORAGE.md) `:153`; FOLLOWUPS `:680-681` | LV-1 landed; compression + white-noise emit **production-live**; read side and plain builders **inert until LV-3** | Defines which half of the dual stack is authoritative per row (§2.2) |

**Two locate-level defects found during the sweep**, both inside
enumerate-don't-fix as *registration hygiene* rather than design changes, and
both fixed in this PR because the index is load-bearing (rule 94):

- `IMPLEMENTATION_INDEX.md:144` links `P2P_REQUIREMENTS_REGISTER.md`; the file
  on disk is `P2P_2_REQUIREMENTS_REGISTER.md` (renamed in `30cd547e2`).
  **Broken link.**
- `SP_T3_SKELETON_MEASUREMENT.md:4` defers its landing status to
  `IMPLEMENTATION_INDEX.md`, but no index row mentions the spike.
  **Dangling status pointer.**

---

## 2. Method — the denominator, its sum check, and the inverse spot-checks

### 2.1 Subjects (named before the walk, per rule 47)

Rule 47 requires a gate to assert its own subject exists; the same discipline
applies to a census, because **absence of a signal is first evidence the
subject is absent, not evidence of a clean surface.** Six subjects were named
up front and each was required to be *found* — a walk that failed to locate
any of them would be reporting on the wrong tree:

| Inverse spot-check subject | Found at | Verdict |
| --- | --- | --- |
| `LEVIN_SIGNATURE` | `rust/shekyl-levin/src/header.rs:14` (`0x0101_0101_0101_2101`), wire bytes pinned by the test at `:189-195` | **FOUND** |
| Handshake field set | `p2p_protocol_defs.h:172-185` (`basic_node_data`), `:198-223` (`COMMAND_HANDSHAKE_T`) | **FOUND** — four fields, post-#587 |
| The NOTIFY pair | `cryptonote_protocol_defs.h:115-130` (2001) and `:265-280` (2008) | **FOUND** — both still present |
| Timed-sync cadence | `cryptonote_config.h:184` (`P2P_DEFAULT_HANDSHAKE_INTERVAL 60`), driven by `net_node.h:618` → `net_node.inl:2023` → `:2063` | **FOUND** — and it is in `net_node.inl`, not the protocol handler |
| Fragmentation | `rust/shekyl-levin/src/fragment.rs:81-127` | **FOUND** — production-live via FFI |
| Compression | `rust/shekyl-levin/src/compress.rs:24-32` | **FOUND** — production-live since 2026-08-06 |

### 2.2 The denominator

Two parts, because they admit different kinds of check.

**(a) Mechanically countable schema surface** — arithmetic, and the sum must
close:

| Surface | Count at pin |
| --- | --- |
| `p2p_protocol_defs.h` — `BEGIN_KV_SERIALIZE_MAP` blocks | 14 |
| `p2p_protocol_defs.h` — KV field lines (excl. BEGIN/END) | 32 |
| `p2p_protocol_defs.h` — `BEGIN_SERIALIZE` blocks / `FIELD`+`VARINT_FIELD` lines | 3 / 10 |
| `cryptonote_protocol_defs.h` — `BEGIN_KV_SERIALIZE_MAP` blocks | 12 |
| `cryptonote_protocol_defs.h` — KV field lines (excl. BEGIN/END) | 40 |
| **C++ KV maps, total** | **26** |
| **C++ KV field lines, total** | **72** |
| `shekyl-levin` — `impl PortableMap` blocks | 22 |
| `shekyl-levin` — exported wire structs | 21 |
| Command-id constants — C++ (`4` p2p + `9` cryptonote) | 13 |
| Command-id constants — Rust (`4` commands.rs + `9` notifies.rs) | 13 |
| `shekyl-levin/src/header.rs` — `pub const` wire constants | 17 |

**Sum check — 26 C++ maps against 22 Rust impls, residual 4, fully
accounted:**

    26 C++ KV maps
     − 22 with a Rust twin
     =  4 unmirrored:  network_address_old        (PWC-F1)
                       connection_entry_base      (PWC-F2)
                       network_config             (PWC-F3)
                       anchor_peerlist_entry_base (PWC-D5)

and in the other direction, Rust's 22 impls = 21 exported structs + the
`NetworkAddress` enum, whose C++ counterpart (`epee::net_utils::
network_address`) lives in `contrib/epee/.../net_utils_base.h`, **outside both
defs headers** — a denominator boundary, recorded here so the residual is not
mistaken for a gap. `NewFluffyBlock` is a type alias over `NewBlock`
(`notifies.rs:44`), which is why 22 impls cover 23 nominal maps.

**Command-id parity closes exactly: 13 = 13.** This is the strongest single
inverse check in the census — it is the axis #587's field-parity residual
lives on, and at this pin the *identifier* half agrees even though the *field*
half is only structurally tested (PWC-D8).

**(b) Behavioral frontier** — not countable the same way, so it is *enumerated*
and the enumeration is the denominator. Rows about absent behavior (no rate
limit, no jitter) are grounded against this frontier and nowhere else:

- `net_node.inl` — 54 `node_server<>::` member definitions; the load-bearing
  set read for this census: `init_config:138`, `store_config:1012`,
  `do_handshake_with_peer:1059`, `do_peer_timed_sync:1153`,
  `is_peer_used:1205/1230`, `make_new_connection_from_anchor_peerlist:1438`,
  `connections_maker:1808`, `make_expected_connections_count:1882`,
  `idle_worker:2021`, `check_incoming_connections:2032`,
  `peer_sync_idle_maker:2063`, `sanitize_peerlist:2088`,
  `handle_remote_peerlist:2121`, `get_local_node_data:2151`,
  `handle_get_support_flags:2164`, `relay_notify_to_list:2177`,
  `drop_connection:2503`, `try_ping:2510`, `try_get_support_flags:2611`,
  `handle_timed_sync:2640`, `handle_handshake:2689`, `handle_ping:2788`,
  `has_too_many_connections:3083`, `gray_peerlist_housekeeping:3108`.
- `cryptonote_protocol_handler.inl` — 38 `t_cryptonote_protocol_handler<>::`
  member definitions, including all nine notify handlers
  (`:519, 533, 718, 822, 852, 967, 1019, 1785, 2485`) and the drop family
  (`drop_connection_with_score:2811`, `drop_connection:2826/2832`,
  `drop_connections:2842`, `on_connection_close:2866`).
- The four levin **invoke** entry points (`net_node.h:476-479`) and the nine
  **notify** entry points (`cryptonote_protocol_handler.h:90-98`) — 13, matching
  the command-id count.
- The per-command payload cap table, `connection_context.cpp:38-72`.
- Idle/cadence timers: `net_node.h:618-622` (5) and
  `cryptonote_protocol_handler.h:183-186` (4).

### 2.3 In-scope decisions recorded, not assumed

- **`net_node.inl` is IN.** The brief said "the protocol handler `.inl`",
  which is ambiguous between two files. The handshake, timed-sync, peerlist
  and connection-management commitments live in `net_node.inl`; excluding it
  would have made the timed-sync-cadence spot-check unable to find its
  subject.
- **`levin_notify.cpp` is OUT, as a recorded exclusion, not a gap.** Its
  emit-side policy was deleted to Rust in #515 and its enqueue path is
  `NoiseQueues::enqueue`; #580 then reworked what remains. The cover/carrier
  cadence is owned by [`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md)
  and `shekyl-relay-privacy`, and a second enumeration here would be a
  duplicate that drifts. **What this census does own** is the wire-visible
  consequence: the `_` padding field and `dandelionpp_fluff` on 2002
  (PWC-C2), and fragmentation/noise sizing (PWC-A9).
- **The persisted peerlist store is IN** — `net_peerlist.cpp`,
  `net_peerlist_boost_serialization.h` — because rule 42's version-constant
  discipline applies to it and #587 exercised exactly that.
- **`contrib/epee` levin transport is IN only where it enforces a wire
  bound** (`levin_protocol_handler_async.h:421-506, 619`); the rest of epee is
  LV-3's migration surface, not a wire commitment.

---

## 3. Buckets and the evidence-class column

Identical bar to the consensus census, deliberately — the two instruments feed
one rewrite, and a second, softer bar would let the p2p surface claim
ratification the acceptance path could not.

| Bucket | Meaning |
| --- | --- |
| 1 | Shekyl-designed; a written spec is the evidence |
| 2 | Ratified — a design round or decision-log entry examined this rule and kept it, **with a pointer** |
| 3 | Recorded deletion disposition that **names the subject** |
| 4 | Open — no locatable record, or a record that fails the bar |

| Class | Meaning | Bucket |
| --- | --- | --- |
| `spec` | Shekyl-designed, written spec | 1 |
| `ratified` | Design round / decision log examined and kept it (pointer required) | 2 |
| `ratified-premise-refuted` | A ratification exists but its factual premise is refuted at the tree | 4 |
| `examined-disposition` | Reviewed on one path only; the row states which path | 4 |
| `KAT-port` | Moved to Rust pinned by vectors. **A seal is not a ratification** | 4 |
| `pinned-not-re-derived` | Value frozen and documented but inherited without derivation | 4 |
| `inherited-defensive` | The tree carries a defence that happens to answer a known attack, but by **inheritance**, with no Shekyl record examining it | 4 |
| `none` | No locatable record | 4 |
| `—` | Bucket-3 rows | 3 |

`inherited-defensive` is **minted by this census** and is the one class the
consensus census did not need. The p2p surface has defences that arrived with
the Monero lineage and are load-bearing against published attacks (PWC-E7).
Rule 16's whole point is that inherited code is not inherited architecture: a
defence nobody here chose is a defence nobody here is committed to keeping,
and it is exactly the thing a rewrite silently drops. Folding these into
`none` would have lost the fact that the tree currently *does* refuse the
attack; folding them into `ratified` would have been a lie.

**The remembered-ratification rule carries over unchanged:** a rule whose only
support is that someone recalls deciding it is **bucket 4**, not bucket 2.

---

## 4. The census

### 4.A Levin framing

| ID | Commitment | Evidence | Class | B | Seeds |
| --- | --- | --- | --- | --- | --- |
| PWC-A1 | `LEVIN_SIGNATURE` is the fixed 8-byte constant `0x0101_0101_0101_2101`, first field of every bucket, connection-fatal on mismatch | `header.rs:14`, `:152-155`; wire-byte test `:189-195` | `none` | 4 | PW-9 |
| PWC-A2 | Bucket header is exactly 33 bytes, field order and little-endianness fixed; anchored by `static_assert(sizeof(bucket_head2)==33)` and the `levin-constant-parity` CI gate | `header.rs:17`, `:134-144`; `levin_base.h` | `KAT-port` | 4 | — |
| PWC-A3 | Exactly one protocol version is spoken (`1`); a peer's version is echoed back verbatim, never negotiated | `header.rs:20`, `:170` | `none` | 4 | — |
| PWC-A4 | Pre-handshake packet limit 256 KiB, raised to the post-handshake limit only by handshake completion | `header.rs:23`; `reader.rs:147`, `:153-169` | `pinned-not-re-derived` | 4 | — |
| PWC-A5 | Post-handshake packet limit is 100 MB (`DEFAULT_MAX_PACKET_SIZE`), inherited, not derived from any largest-legitimate-message argument | `header.rs:27`; `levin_base.h:86` | `pinned-not-re-derived` | 4 | PW-10 |
| PWC-A6 | **Unknown header flag bits are preserved verbatim** so decode/encode is byte-identical — a covert channel between colluding peers across an honest relay, for a protocol with one implementation | `header.rs:29-30`, `:46-50`; test `:214-229` asserts the preservation as a *requirement* | `none` | 4 | PW-11 |
| PWC-A7 | `return_code: i32` rides every bucket, including notifications where it is always 0 — an RPC-over-Levin affordance | `header.rs:102-103`, `:119` | `none` | 4 | PW-12 |
| PWC-A8 | `expect_response` is carried as a raw truthy `uint8_t`, not narrowed to `bool`, so a sender's `0x02` re-encodes unchanged | `header.rs:96-99`, `:128-130` | `spec` | 1 | — |
| PWC-A9 | Noise/fragment emit pads every message to exactly `noise_size`; fragment headers claim a full body, command `0`, B/E on first/last, middles flagless | `fragment.rs:47-127` | `KAT-port` | 4 | — |
| PWC-A10 | Compression is zstd level 1, floor 256 B, inflate bounded by `min(packet limit, per-command limit)`; **compression precedes encryption in any future transport**, a CRIME/BREACH-class oracle that interacts with D++ padding | `compress.rs:24-32`, `:62-70` | `none` | 4 | PW-13 |
| PWC-A11 | The reader latches on framing error (`Error::Poisoned`), and verifies the inner reassembled fragment signature the C++ `memcpy`s unchecked — both **stricter** than the oracle | `lib.rs:79-112` (divergence census entries 1-2, 5) | `spec` | 1 | — |

### 4.B p2p command schemas (1001 / 1002 / 1003 / 1007)

| ID | Commitment | Evidence | Class | B | Seeds |
| --- | --- | --- | --- | --- | --- |
| PWC-B1 | Four p2p commands exist: 1001 handshake, 1002 timed-sync, 1003 ping, 1007 support-flags. **1004-1006 are unallocated** — an absence, verified by the gap in the ID sequence at both stacks | `p2p_protocol_defs.h:196, 232, 267, 299`; `commands.rs:18-24` | `none` | 4 | — |
| PWC-B2 | `basic_node_data` carries exactly four fields: `network_id`, `peer_id`, `my_port`, `support_flags` | `p2p_protocol_defs.h:172-185`; `types.rs:18-27` | `none` | 4 | — |
| PWC-B3 | `rpc_port` and `rpc_credits_per_hash` are **absent** from the handshake and from peerlist entries — deleted as contrary to RT-9's no-public-RPC-advertisement posture | #587 (`cf3b13c29`); `RPC_TRANSPORT_POSTURE.md:559` UPDATE 2026-08-31; absence confirmed at `p2p_protocol_defs.h:172-185` | `ratified` | **2** | PW-14 |
| PWC-B4 | Handshake response carries the peerlist; timed-sync response carries it again — two peerlist-disclosure surfaces, not one | `p2p_protocol_defs.h:214`, `:246`; `commands.rs:65`, `:119` | `none` | 4 | PW-16 |
| PWC-B5 | `support_flags` advertises `FLUFFY_BLOCKS(0x01) \| ZSTD_COMPRESSION(0x02)`; a peer reporting 0 is re-queried out-of-band via 1007 | `cryptonote_config.h:257-259`; `net_node.inl:2771-2775`, `:2611-2637` | `none` | 4 | — |
| PWC-B6 | Ping response echoes the responder's `peer_id`, and the back-ping caller **requires it to match** the handshake-advertised id or closes | `p2p_protocol_defs.h:280-290`; `net_node.inl:2585-2590` | `none` | 4 | PW-19 |
| PWC-B7 | `my_port` is zeroed when `--hide-my-port` is set or the zone cannot pingback; the back-ping is skipped entirely when it is 0 | `net_node.inl:2151-2160`, `:2512-2513` | `none` | 4 | — |

### 4.C cryptonote notify schemas (2001-2010)

| ID | Commitment | Evidence | Class | B | Seeds |
| --- | --- | --- | --- | --- | --- |
| PWC-C1 | Nine notify commands: 2001-2004, 2006-2010. **2005 was never allocated** — recorded in the Rust as an explicit comment, absent in the C++ | `cryptonote_protocol_defs.h`; `notifies.rs:23` | `none` | 4 | — |
| PWC-C2 | `NOTIFY_NEW_TRANSACTIONS` carries `_` (padding, always stored even when empty) and `dandelionpp_fluff` (OPT, default **true**) — the stem/fluff bit is **in the clear on the wire** | `cryptonote_protocol_defs.h:141-149`; `notifies.rs:70-100`; `DAEMON_RELAY_PRIVACY.md:10758-10787` | `ratified` | **2** | — |
| PWC-C3 | `NOTIFY_NEW_BLOCK` (2001) still exists alongside `NOTIFY_NEW_FLUFFY_BLOCK` (2008) — two block-propagation paths that must agree on validation, on a chain with **no fluffy-block transition to justify the legacy one**. Both present at this pin; both dispatched (`handler.h:90`, `:96`) | `cryptonote_protocol_defs.h:115`, `:265`; handlers `.inl:519`, `:533` | `none` | 4 | PW-27 |
| PWC-C4 | `block_complete_entry.attestation_witness` is bounded **at the codec**, not at callers, so no p2p ingress can bypass the cap; the Rust twin duplicates the constant `8 + 256*3385 = 866_568` with a `const _: () = assert!` | `cryptonote_protocol_defs.h:97-105`; `block.rs:23-25`, `:73-82` | `spec` | 1 | — |
| PWC-C5 | `CORE_SYNC_DATA` stores `cumulative_difficulty_top64` **unconditionally on store, OPT on load** — an asymmetry both stacks must reproduce exactly | `cryptonote_protocol_defs.h:205-208`; `types.rs:52`, `:91-95` | `KAT-port` | 4 | — |
| PWC-C6 | `pruning_seed` rides `CORE_SYNC_DATA` and every peerlist entry, and is validated on ingest against the stripe range | `cryptonote_protocol_defs.h:200`; `net_node.inl:2105` | `none` | 4 | — |
| PWC-C7 | Per-command payload caps are a 13-entry switch; **unknown commands fall through to `size_t::max`**, leaving only the packet limit. The two 128 MB entries exceed the 100 MB packet limit by design, as their own comments note | `connection_context.cpp:38-72` | `pinned-not-re-derived` | 4 | — |
| PWC-C8 | `block_complete_entry` serializes `txs` two different ways — object array when `pruned`, blob array otherwise — and the unpruned load path fills `prunable_hash` with zeros | `cryptonote_protocol_defs.h:76-96`; `block.rs:92-125` | `KAT-port` | 4 | — |

### 4.D Peerlist, peer identity, persisted store

| ID | Commitment | Evidence | Class | B | Seeds |
| --- | --- | --- | --- | --- | --- |
| PWC-D1 | Peerlists are disclosed up to `P2P_MAX_PEERS_IN_HANDSHAKE = 250` per message; a peer sending more is refused as spamming | `cryptonote_config.h:186-187`; `net_node.inl:2123-2127` | `none` | 4 | PW-16 |
| PWC-D2 | The disclosed head is **anonymized**: sampled over the whole white list, shuffled, truncated to depth, `last_seen` zeroed — an explicit defence citing Cao et al. eprint 2019/411 | `net_peerlist.h:296-331` | `inherited-defensive` | 4 | PW-16 |
| PWC-D3 | White list capped at 1000, gray at 5000, both evicting by oldest `last_seen` | `cryptonote_config.h:175-176`; `net_peerlist.h:219-232` | `pinned-not-re-derived` | 4 | — |
| PWC-D4 | `peer_id` is a per-process random `uint64` regenerated at every start, **never persisted**; anonymity zones use the fixed sentinel `1` | `net_node.inl:147`; `net_node.h:180`, `:309` | `none` | 4 | PW-14, PW-19 |
| PWC-D5 | The anchor list keys on `(adr, id, first_seen)` and is **persisted**, but its KV map is never sent — anchors reach the wire through no command | `p2p_protocol_defs.h:93-112`; `net_peerlist.cpp:156` | `none` | 4 | PW-18 |
| PWC-D6 | Outbound connection-continuity matching uses **address**, with `peer_id` only a secondary public-zone check — existing code already treats address as bookkeeping, distinct from trust-by-identity | `net_node.inl:1219`, `:1244` | `none` | 4 | PW-18 |
| PWC-D7 | Persisted store version is 7 with **drop-on-load** and no migration shim; `peerlist_entry` boost version is 4 with a local `ver < 4` throw. The drop includes the anchor list, so one bootstrap runs without anchor-set eclipse resistance | `net_peerlist.cpp:53`, `:84`; `net_peerlist_boost_serialization.h:44`, `:217-224`; #587 body | `ratified` | **2** | — |
| PWC-D8 | The dual stack's **field parity is structurally tested, not byte-pinned**: `payload_kats` asserts round-trips and the deleted-fields pin, but the C++ emitter half is covered only by the `#[ignore]`d live `dual_stack.rs` run | #587 body ("it does **not** cover the C++ emitter"); `lib.rs:44-47` | `examined-disposition` | 4 | LV-3 |
| PWC-D9 | `sanitize_peerlist` drops loopback/local, and for **IPv4 only** drops `ip == 0 \|\| port == 0`. The ipv6/tor port-0 asymmetry is pre-existing and tor's port-0 semantics are disputed (`tor_address::unknown()` is port 0) | `net_node.inl:2088-2118`; #587 body names it for this census | `examined-disposition` | 4 | — |
| PWC-D10 | A peerlist whose entries are not all from the sender's own zone is refused wholesale | `net_node.inl:2132-2140` | `none` | 4 | — |
| PWC-D11 | A peer is added to the white list **only after a successful back-ping**, which is the sole path from inbound contact to white-list membership | `net_node.inl:2741-2769`; `p2p_protocol_defs.h:262-266` | `inherited-defensive` | 4 | — |

### 4.E Connection management and cadence (behavioral)

| ID | Commitment | Evidence | Class | B | Seeds |
| --- | --- | --- | --- | --- | --- |
| PWC-E1 | Timed-sync fires on a **fixed 60 s** cadence with no jitter, to every handshaked connection at once | `cryptonote_config.h:184`; `net_node.h:618`; `net_node.inl:2023`, `:2063-2085` | `none` | 4 | PW-28 |
| PWC-E2 | **There is no rate limit on Ping, Timed-Sync or handshake.** Verified as an absence against the enumerated frontier (§2.2b): no token bucket, no per-peer counter, no minimum interval guards any of the four invoke entry points | `net_node.h:476-479` handlers `net_node.inl:2640`, `:2689`, `:2788`, `:2164` — none consults a rate structure | `none` | 4 | PW-15 |
| PWC-E3 | Five node-server idle timers: handshake 60 s, connections-maker 1 s, gray housekeeping 60 s, peerlist store 1800 s, incoming-connections check 3600 s — all fixed, none jittered | `net_node.h:618-622` | `pinned-not-re-derived` | 4 | PW-28 |
| PWC-E4 | Four protocol-handler timers: idle-peer kick 8 s, standby check 100 ms, **sync search 101 s**, bad-peer check 43 s | `cryptonote_protocol_handler.h:183-186` | `pinned-not-re-derived` | 4 | — |
| PWC-E5 | Idle peers are kicked at 240 s since last request (`IDLE_PEER_KICK_TIME`); peer score starts at 0 and a peer is dropped at `DROP_PEERS_ON_SCORE = -2` | `cryptonote_protocol_handler.inl:80`, `:85`, `:2715-2725` | `pinned-not-re-derived` | 4 | — |
| PWC-E6 | Outbound budget: `WHITELIST_CONNECTIONS_PERCENT = 70` white / remainder gray, with `ANCHOR_CONNECTIONS_COUNT = 2` filled first; the default out-degree itself is **Rust-owned** via `shekyl_p2p_default_out_peers()` | `cryptonote_config.h:193-195`, `:178-183`; `net_node.inl:1828-1839` | `ratified` | **2** | PW-17 |
| PWC-E7 | **A double-spend is a no-drop offense**: a conflicting tx sets `m_verifivation_failed` *and* `m_no_drop_offense`, and `handle_notify_new_transactions` drops only when `!m_no_drop_offense`. The check is against the **pool's** `m_spent_key_images`, so it covers a pool-held conflict, not only a chain-spent one | `tx_pool.cpp:282-292`, `:1676-1696`; `cryptonote_protocol_handler.inl:926-931`; provenance `f7fd209ed` (jeffro256, 2024-03-07) | `inherited-defensive` | 4 | §5.2 |
| PWC-E8 | Four other tx classes are also no-drop offenses: fee-too-low, oversized `tx_extra`, non-zero unlock time, double-spend | `tx_pool.cpp:257, 267, 276, 291` | `inherited-defensive` | 4 | — |
| PWC-E9 | `drop_connections(address)` drops **every** connection sharing a host and adds a host-fail score of 5. Four call sites, all on the block-sync path: prepare-failure, tx-parse failure, verification failure, orphaned block | `cryptonote_protocol_handler.inl:1467, 1494, 1528, 1548`, definition `:2842-2863` | `none` | 4 | §5.2 |
| PWC-E10 | Host blocking: 10 fails before block, 24 h block time; failed-address suppression is 1 h public / 240 s anonymity-zone, the latter **derived at the p90 of measured Tor post-restart recovery** with the derivation recorded beside the constant | `cryptonote_config.h:199-255` | `ratified` | **2** | — |
| PWC-E11 | `has_too_many_connections` caps inbound per host at `--max-connections-per-ip` (default 1) and **only on the public zone** — it returns false, i.e. permits, on every anonymity zone | `net_node.inl:3083-3105`; `net_node.cpp:179` | `examined-disposition` | 4 | — |
| PWC-E12 | An arrival is stemmed **whatever transport it arrived on**; the inherited `forward` class and its clearnet-bridge delay were deleted with their mechanism | `cryptonote_protocol_handler.inl:885-926`; `cryptonote_config.h:145-166`; Q12-U2 (PR #459) | `ratified` | **2** | — |
| PWC-E13 | Relay-to-list compresses once and reuses the buffer across every recipient, choosing compressed only when strictly smaller | `net_node.inl:2177-2206` | `none` | 4 | PW-13 |
| PWC-E14 | Self-connection is detected by `peer_id` equality **on the public zone only** — deliberately, so an attacker cannot confirm a clearnet/tor co-identity by observing a rejection | `net_node.inl:2718-2725`, `:1114-1119` | `inherited-defensive` | 4 | PW-19 |

### 4.F Dead and latent wire surface

| ID | Commitment | Evidence | Class | B | Disposition candidate |
| --- | --- | --- | --- | --- | --- |
| PWC-F1 | `network_address_old` (`ip`, `port`) has **no caller** outside `debug_utilities/object_sizes.cpp` — a pre-typed-address fossil | `p2p_protocol_defs.h:58-67`; only refs `object_sizes.cpp:91-92` | `—` | **3** | Rule 60 names pre-genesis dead-branch removal; deletion candidate for P2P-2 |
| PWC-F2 | `connection_entry_base` / `connection_entry` has **zero callers tree-wide** — no producer, no consumer, not even the size printer. Plausibly stranded when RK-5a deleted `connection_info` / `get_connections()` | `p2p_protocol_defs.h:114-133`; tree-wide grep returns only the definition | `—` | **3** | Deletion candidate; the RK lane should confirm it is RK-5a's residue |
| PWC-F3 | `network_config`'s KV map is **never sent** — the struct is local config (`net_node.h:313`). Latent, and it would advertise `packet_max_size = P2P_DEFAULT_PACKET_MAX_SIZE = 50 MB` while the **enforced** limit is `LEVIN_DEFAULT_MAX_PACKET_SIZE = 100 MB` — a 2× disagreement that is harmless only because nothing serializes it | `p2p_protocol_defs.h:152-170`; `cryptonote_config.h:185`; `net_node.h:388`; `levin_base.h:86` | `none` | 4 | Delete the map, or reconcile the constants — **not both left as-is** |
| PWC-F4 | The KV map serializes 5 of `network_config`'s 8 members; `ping_connection_timeout`, `connection_timeout` and `send_peerlist_sz` are unserialized | `p2p_protocol_defs.h:154-169` | `none` | 4 | Subsumed by PWC-F3's disposition |

---

## 5. The register's §7 tasks, run as census work

### 5.1 Task 1 — PW-17's tenure split against §12.10's actual mechanism

**Verdict: the split is neither confirmed nor falsified by §12.10, because
§12.10 does not contain the mechanism PW-17 asks to be checked against.**

Read in full at this pin: §12.10 is `:2480-2542`. Its content is
work-based admission (`:2488-2500`), the two-`g_max` split (`:2502-2506`), the
three-regime eclipse table (`:2508-2512`), the pool-share consequence
(`:2514-2520`), a thin pinning-is-safe passage (`:2522-2532`), and Q4 reframed
(`:2534-2541`). **Anchors appear in exactly one line (`:2512`), inside the
full-eclipse row.** There is no inbound-vs-outbound tenure specification
anywhere in the section.

The material PW-17 actually needs is **outside** §12.10: §6.10 `:1009-1022`
(behavioural floor, guard-pinning, `ANCHOR_CONNECTIONS_COUNT = 2` as seed,
address family ruled out as an admission basis) and `:1024-1042` (the pinning
tax), plus §7 `:1333-1416` (pinning as structural lever; `:1380-1385`
pin-vs-epoch layering, `:1386-1394` the anchor relationship, `:1395-1399` pin
lifetime, `:1400-1403` re-draw at formation).

So PW-17's status is **corrected, not resolved**: it is not "verify against
§12.10", it is "verify against §6.10 + §7, which is where the mechanism lives."
Recorded as PWC-X4. The verification itself is P2P-2's, and it now has the
right pointers.

Two further cautions the read surfaced, both of which would have silently
corrupted a P2P-2 round that trusted §12.11 as current spec:

- §12.11 carries **two superseding banners** (`:2545-2553`, `:2555-2574`): the
  Exploit tier is **deleted** as D++ §4.5 version-checking, and the mechanism
  reduces to a **uniform random draw over the non-cooled admissible set**
  (§§52/53/54 at `:9484`, `:9607`, `:9713`). The body below the banners reads
  as live spec and is not.
- `ρ` is **not mentioned in §12.10 at all.** The register attributes the
  underspecified-blocked-on-Q-10 status to it; the actual statements are at
  `:37-41` (status header), `:1254-1265`/`:1286-1292`/`:1327-1332` (§7),
  `:1293-1308`, `:2080-2090` (§12.6) and the canonical `:2872-2890` (§13.5,
  "`ρ` is *underspecified*, not *undecided-pending-judgment*"). PW-25's claim
  survives; its citation does not.

### 5.2 Task 2 — `drop_connections` against the Shi et al. mechanism

The paper was **not in the local corpus** and the register cites it only by
paraphrase, so it was fetched and read at source rather than checked against a
summary: Shi, Peng, Lan, Ge, Liu, Wang, Wang, *Eclipse Attacks on Monero's
Peer-to-Peer Network*, NDSS 2025.

**The attack as the paper actually states it** (§III): 1,020 public IPs, no
target restart, minutes to completion, in three sub-attacks —
① **graylist attack** (§III-A): 20 inbound connections carry 250 trash peer
records each in delayed timed-sync responses, filling the 5,000-entry FIFO
graylist; ② **whitelist attack** (§III-B): 1,000 IPs cycled as inbound
connections so their records re-enter the whitelist with refreshed `last_seen`,
which is what makes them preferred for outbound selection; ③ **connection
reset** (§III-C): force the victim to drop its benign peers, whereupon it
refills outbound slots from the now-poisoned whitelist.

③ has two arms, and **the census verdict differs between them:**

- **Private-transaction arm** — requires the victim to expose RPC and accept
  `send_raw_transaction(do_not_relay=true)`, which the paper says means nodes
  started with `--public-node`. **Structurally inapplicable to Shekyl:** RT-9
  removed `--public-node` and `/get_public_nodes`
  (`RPC_TRANSPORT_POSTURE.md:333-373`, ruled 2026-08-21), and #587 finished the
  disposition by deleting the P2P-side advertisement. This arm has no entry
  point here. Class `ratified` — the removal was examined and recorded.
- **Dandelion++ arm** — transport-independent, applies to every node. Proxy
  sends stem `tx1` to the victim and simultaneously fluffs conflicting `tx2` to
  the network; the victim's neighbours forward `tx2` back, and **the
  double-spend conflict is what drops the connections.**

**Against the D++ arm, the tree currently refuses the drop.** `handle_notify_
new_transactions` drops only on `!tvc.m_no_drop_offense`
(`cryptonote_protocol_handler.inl:926-931`), and the pool sets
`m_no_drop_offense = true` on exactly the double-spend path
(`tx_pool.cpp:282-292`). The guard condition was checked rather than assumed:
`have_tx_keyimges_as_spent` consults the **pool's** `m_spent_key_images`
(`tx_pool.cpp:1676-1696`), which is the paper's case — `tx1` sitting in the
pool when `tx2` arrives — not merely a chain-spent image.

**This is `inherited-defensive`, not a pass.** The commit is
`f7fd209ed` — *"tx_memory_pool: make double spends a no-drop offense"*,
jeffro256, **2024-03-07**, i.e. upstream Monero's own response, predating the
paper's publication. Shekyl has no record examining it. Under rule 16 that
makes it a defence we inherited and have not chosen: **a rewrite that
re-derives the tx-ingest path from the census would drop it silently unless
this row exists.** That is precisely what PWC-E7 is for.

Three residues stay open and are not closed by the above:

1. **Sub-attacks ① and ② are unaddressed.** The graylist is FIFO-5000 and
   accepts unvalidated records from timed-sync responses (PWC-D3, PWC-D10);
   the whitelist re-entry path is the back-ping (PWC-D11). The paper's
   countermeasures (§VII-A) — restrict timed-sync peerlists to outbound
   connections, or cap records per connection — are **unimplemented here**.
2. **`update_sync_search()`'s 101 s random non-anchor disconnect**, which the
   paper names as an independent connection-dropping lever (§II-D3), is present
   at this pin as `m_sync_search_checker` (PWC-E4).
3. **`drop_connections` remains reachable on the block path** (PWC-E9): four
   sites, each dropping *every* connection sharing a host, with a host-fail
   score of 5. The paper's arms are tx-shaped, so these are not the same lever
   — but they are the same *shape* of lever, and no equivalent
   no-drop-offense analysis has been done for block-path failures.

### 5.3 Task 3 — PW-22's reading list: does the firewall cover submission?

**Verdict: the coverage gap is real and remains open; the reading closes the
question of where it is, not what it is.**

The reading list was worked at this pin. `derive_socks_user` is confirmed
**still at `rust/shekyl-p-transport/src/lib.rs:134`**, deriving a per-persona
SOCKS username by cSHAKE256 over the full canonical `P` id, with consumers in
`shekyl-tor/tests/circuit_isolation.rs:172, 450-453`. The GF-7 cover-blindness
finding is at [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md)
`:2004-2032` — worst-arm `r ≈ 1.86` flat across `N ∈ [2,16]`, `r < 2`
structurally blind to cover; **the finding stands, only the instrument was
made fail-closed** (2026-07-23). The cover-is-always-protocol-added ruling is
**not** in that document — it is
[`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md) `:410-427`,
maintainer-corrected 2026-07-22 (DS-PR-2). The SH arc's own doc
([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §9.7
`:1720-1850`, custody anchors `:885`, `:969`) states the serving host receives
**derived bundles only** — it speaks to serving and is silent on submission.

So: the P-transport lane denies persona linkage **for the paths it covers**,
and no document in the reading list extends that to the serve-credit
submission path. The submission path itself is in the clear by design
(`blockchain.cpp:5314` reads `sc_p_id` straight off the vin). The gap is
therefore **located and confirmed open**, and it is a *design* question for
P2P-2, not a census finding — recorded as PWC-X5. The one thing this census
adds: the SP-T lane is **partially built and inert** (index `:178` —
`PTorClient`/`PBlockSource` on `dev` under `dead_code`), so there is no
production submission path to have covered it yet.

### 5.4 Task 4 — must guard-pinning survive a full reconnect?

**Answer at the tree: yes, and it already does — but by address, and only
across restarts, not within a session.**

Anchors are persisted (`net_peerlist.cpp:156`), reloaded at start, and dialled
before the general peerlist (`net_node.inl:1839`). Anchor selection
(`:1438-1469`) keys on `pe.adr` for the used/allowed/recently-failed checks and
carries `first_seen` purely as a log value — `is_peer_used(anchor_peerlist_
entry)` (`:1230-1252`) matches outbound connections on `peer.adr ==
cntxt.m_remote_address`, with `peer.id` consulted only on the public zone.

So the cross-reconnect recognition key PW-17 wondered about **exists today and
is the address**, which is consistent with PW-18's rule that the recognition
key is never a wire field: nothing about anchor tenure is serialized to a peer.
`ANCHOR_CONNECTIONS_COUNT = 2` is the seed count, not a tenure duration.

The caveat that matters for P2P-2: **#587's store bump drops the anchor list
on first load after upgrade**, so anchor tenure does not survive a store
version change — one bootstrap runs without it (PWC-D7). Recorded as PWC-X6.

### 5.5 Task 5 — PW-3's pattern attribution

**Not runnable as census work, and recorded as such rather than guessed.** The
NoisePQC++ table (`2608.00954v1_Noise_PQC.pdf`) is not in the repository;
it is in the maintainer's local reference corpus
(`~/Nextcloud/Documents/`), outside this census's pinned subject. The register's
own instruction stands unchanged — re-read the table before quoting any
pattern's byte count in the P2P-2 brief; the ~14× magnitude is not what is in
doubt, the NN-vs-XX attribution of the 192 B classical figure is. Recorded as
PWC-X7, owner P2P-2.

---

## 6. PW-row accounting — seeds, and where the tree does not confirm them

PW rows are **seeds, not substitutes**: every one is cited by id and none is
carried forward on the register's authority alone. All 28 resolve here.

| PW | Disposition at this pin |
| --- | --- |
| PW-1, PW-2, PW-6, PW-7 | **Off-tree** — literature/prior-art claims about Noise/PQC with no Shekyl code to census. Carried to P2P-2 unexamined by this instrument |
| PW-3 | **Not verifiable here** — see §5.5 (PWC-X7) |
| PW-4, PW-5 | **Off-tree**, and conditional on a pattern choice not yet made. See §7 note |
| PW-8 | **Ruled (gossip) in the register**, no tree surface yet — no rekey mechanism exists on this wire to census |
| PW-9 | **CONFIRMED** → PWC-A1 |
| PW-10 | **CONFIRMED** → PWC-A5, and **extended**: a second, disagreeing packet-size constant exists (PWC-F3) |
| PW-11 | **CONFIRMED** → PWC-A6; the preservation is asserted by a test, so it is a requirement, not an accident |
| PW-12 | **CONFIRMED** → PWC-A7 |
| PW-13 | **CONFIRMED** → PWC-A10, PWC-E13 |
| PW-14 | **HALF REFUTED AT THE TREE.** `rpc_port` is **gone** (#587) — the register's `p2p_protocol_defs.h:180-196` pointer no longer resolves to it. The `peer_id` half stands → PWC-D4 |
| PW-15 | **CONFIRMED as an absence** → PWC-E2, grounded against the enumerated frontier per rule 47 |
| PW-16 | **CONFIRMED and narrowed** → PWC-D1, PWC-B4; the disclosure is **anonymized** (PWC-D2), which the register's "full 250-peer list" phrasing understates |
| PW-17 | **RE-POINTED, not resolved** → §5.1, PWC-X4 |
| PW-18 | **CONFIRMED** → PWC-D5, PWC-D6; the register's `net_node.inl:1225` pointer is `:1219` at this pin |
| PW-19, PW-19a | **CONSISTENT with the tree** → PWC-D4, PWC-B6, PWC-E14. Citation block folded below |
| PW-20, PW-21 | **Off-tree** — Sybil-replacement scope and a rejected proposal; no wire surface |
| PW-22 | **LOCATED, still open** → §5.3, PWC-X5 |
| PW-23, PW-23a, PW-24, PW-25, PW-26 | **Designed, not built** — nothing to census; PW-25's `ρ` citation corrected in §5.1 |
| PW-27 | **CONFIRMED** → PWC-C3, at `:115` / `:265` (register said `:184` / `:334`, pre-#587 line numbers) |
| PW-28 | **CONFIRMED** → PWC-E1, PWC-E3; every cadence on this surface is fixed and unjittered |

**Fail-to-find is reported, not reconciled.** Three register pointers do not
resolve at this pin — PW-14's `rpc_port`, PW-27's line numbers, PW-18's
`:1225` — and one register claim is refuted outright (PW-14's `rpc_port` half).
The dispatch brief's own premise that **Q12-U1/U2 are open** is likewise
refuted (PWC-X1). None of these were silently corrected upstream.

### 6.1 PW-19a's citation block, folded in as this row's evidence

The no-authentication-between-unknown-peers constraint has **no single landed
sentence**; three independent rulings jointly entail it, and that is how it is
cited — jointly, which is stronger than one sentence and inoculates against
the "but no doc actually says it" form of re-litigation:

1. **Scope** — `RPC_TRANSPORT_POSTURE.md` §2.1 (`:101-107` at this pin; the
   register's `:99-106` is one line short): "The peer-to-peer layer talks to
   strangers by construction… P2P is adversarial by design and hardened
   separately."
2. **Mechanism** — `DAEMON_RELAY_PRIVACY.md` §12.10 (`:2480`, `:2498`):
   admission is "transport-blind (work, not identity)"; `:7396` confirms the
   toll is paid in work precisely so a fresh peer needs no cross-session
   identity.
3. **Anti-ruling** — `Q12_D6A_PEER_DISCOVERY_RUN.md` (`:2910-2917`): a stable
   p2p-layer identity "would hand back the linkage the transport layer is
   built to deny", with identity-as-signal rejected twice (`:2979`, `:3013`).

The tree is **consistent with all three**: `peer_id` is per-process random and
never persisted (PWC-D4), anchor tenure keys on address and is never
serialized (PWC-D5/D6), and self-detection is deliberately public-zone-only so
a rejection cannot confirm a co-identity (PWC-E14).

---

## 7. Cross-cutting rows and what this census does not cover

| ID | Record |
| --- | --- |
| PWC-X1 | Q12-U1/U2 are **LANDED (PR #459)**, not open as the dispatch brief assumed; U2 is visible at `cryptonote_protocol_handler.inl:885-926` |
| PWC-X2 | The E′/MS-5 lane is **multisig**, not p2p transport; every "transport blob" hit is a file envelope or a consensus blob. Searched so it need not be searched again |
| PWC-X3 | `IMPLEMENTATION_INDEX.md:242` still stamps #580 as "verified on `feat/carrier-producer`, NOT on `dev`". It merged as `63d543103`; the stamp is stale |
| PWC-X4 | PW-17's verification target is **§6.10 + §7**, not §12.10 (§5.1) |
| PWC-X5 | PW-22's submission-vs-serving coverage gap is **located and open**; no production submission path exists yet (§5.3) |
| PWC-X6 | Anchor tenure survives restart but **not a store version bump** (§5.4) |
| PWC-X7 | PW-3's pattern attribution is not verifiable from the repository (§5.5) |
| PWC-X8 | §12.11's body is **superseded in part** by two banners; the live selection mechanism is a uniform draw over the non-cooled admissible set (§§52/53/54) |

**Deliberately out of scope**, each with a reason rather than by omission:

- **The future transport itself.** PW-1…PW-8 concern a hybrid-PQ Noise
  transport that does not exist in the tree. A census enumerates what is
  there; the transport's design is P2P-2's deliverable. Note for that round:
  PW-4 and PW-5 are both *conditional on statics existing in the chosen
  pattern*, so a pattern with no static keys leaves them without a subject —
  but that is a design consequence to be ruled on with the pattern, not a
  census finding, and this census does not rule it.
- **`levin_notify.cpp` / carrier cadence** — §2.3, owned by
  `COVER_TRAFFIC_RESTORATION.md` and `shekyl-relay-privacy`.
- **The epee `portable_storage` codec** — LV-2a's surface
  (`shekyl-portable-storage`), censused by its own lane.
- **RPC** — the §2.1 boundary; `RPC_TRANSPORT_POSTURE.md` governs.
- **Consensus rules reachable from a p2p message.** Block and tx *acceptance*
  is the consensus census's denominator
  ([`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md)); this census stops
  at the wire and at the connection-management behavior around it. The one
  deliberate crossing is PWC-E7/E8, where a *pool* verdict determines a
  *connection* outcome — recorded here because the drop is the p2p-visible
  half and the consensus census would have no reason to carry it.

---

## 8. Totals

**55 bucketed rows: 3 bucket-1, 6 bucket-2, 2 bucket-3, 44 bucket-4** — by
group, PWC-A×11 (2/0/0/9), B×7 (0/1/0/6), C×8 (1/1/0/6), D×11 (0/1/0/10),
E×14 (0/3/0/11), F×4 (0/0/2/2). The eight `PWC-X` cross-cutting records carry
no bucket, so they are excluded from the totals rather than padding them.

The substantive result is the **bucket-1 + bucket-2 share: 9 of 55, 16 %.**
Set against the consensus census's 101 of 171 (59 %) at the same bar, that is
the census's one real finding about the surface as a whole — **the p2p wire is
the least-examined surface in the tree**, and the gap is concentrated in
bucket 1: the acceptance path is 51 % Shekyl-designed-with-a-spec, this wire is
5 %. Nearly everything here arrived with the lineage.

Two qualifications, so the number is not read as more than it is. It counts
rows, not risk — PWC-A6's covert channel and PWC-E2's absent rate limit are
one row each, as is `expect_response`'s raw byte. And every bucket-2 row on
this surface was ratified within the last six weeks (#587, RT-9, Q12-U2, the
anonymity-zone retry constant, the D++ fluff bit), so the ratified fraction is
better read as *how recently anyone looked* than as accumulated diligence.
