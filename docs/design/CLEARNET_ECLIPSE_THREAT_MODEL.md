# Clearnet eclipse: threat model, Tor unavailable

**Status:** OPEN — working draft, Round 0 not opened. One rule in it is ruled:
- **An IPv6 host is its /64.** Ruled for the clearnet accept-rate bound (Rick, 2026-10-30; #1226; `P2P_TRANSPORT_LAYER.md` D10.3). Adopted on 2026-10-27 as the first step of this round, for every per-host rule in §5 item 1.

Everything else here is a working draft, for the round to rule.
**Premise (Rick, 2026-10-27):** worst case, Tor is not available. The clearnet connector has to stand on its own; switching to Tor avoids the problem rather than fixing it.
**Read at:** `dev` `c72048125`. Every anchor was re-verified at `90ef1bc9ae` (2026-10-30). The reconnect throttle is cited by its heading, not a line.
**Clearnet authentication:** clearnet can encrypt and recognize, but never authenticate a destination (Rick, 2026-10-26). Every on-path residual below is permanent and accepted, not pending.

## 1. What "capture all paths" means, and what it buys

An eclipse is the state in which every session a node holds, outbound and inbound, is with the attacker or passes through the attacker. Once eclipsed, the attacker can:

- **Learn the origin of every transaction the node sends.** The stem's first hop is the attacker's. This needs no hashpower.
- **Withhold blocks and transactions.** The node stalls on a stale tip. This needs no hashpower.
- **Feed the node a fork.** Every block still has to meet the node's own difficulty check, so a double-spend against an eclipsed merchant costs real hashpower for as long as the fork has to last. An eclipse cheapens this but does not remove the cost.
- **Use the node as a partition point.** Its relaying amplifies selfish mining or a split.

There are two different ways to capture a node, and they need different positions:

- **Logical capture (any node can try it).** The attacker never touches our packets. It makes our own dialer choose only attacker peers, by owning our peer lists. This is the Heilman et al. Bitcoin eclipse and the Marcus et al. Ethereum eclipse. It is the realistic threat from "another node".
- **On-path capture (needs a network position).** The attacker carries our packets: our LAN, our gateway or our ISP, or a BGP interception of our prefix or our peers' prefixes. A node on the internet cannot do this unless it holds one of those positions.

## 2. Logical capture against our code, step by step

### Step 1: identities are free

- **A host is the full IP.** `NetworkAddress::host()` returns `Host::Ip` of the exact address (`shekyl-net-address`), so one IPv6 /64, the standard allocation on a $5 VPS, is 2^64 distinct hosts. Every per-host rule fails against it:
  - one candidate per host (`Peerlist::draw_gray_where`);
  - one outbound session per host (`candidate.rs:70`, `outbound_hosts`, `Attempts::holds_host`);
  - host bans (`shekyl-transport-layer/src/ban.rs`). These cover a host or an `Ipv4Subnet` only; there is no IPv6 range ban.
- **Address validity** admits every global IPv6 address (`validity.rs`). That is correct for validity, but it means nothing upstream of the host rules bounds the count.
- **There is no grouping:** "no subnet grouping" (`candidate.rs:14`, ruled 2026-10-11; D1 and D2 withdrawn, to be reopened on PM-2a's clearnet many-address run).

### Step 2: filling gray costs almost nothing

- **Any established session can feed gray, inbound ones included.** `peer_sync_idle_maker` (`net_node.inl:686`) sends a timed sync on every established connection. The response's list goes to `received_peerlist` → `shekyl_peerlist_admit_received` → `admit_received_list` (`zone_server.h:196`, `peerlist_ffi.rs:159`). An attacker only has to connect to us.
- **The intake cap is per session, and a reconnect resets it.** D-S1 allows 24 distinct addresses per session per 24 h (`SESSION_INTAKE_CAP`, `peerlist.rs:218`, `:288`), and "the session ended; its intake ledger goes with it" (`peerlist.rs:312`). The design doc names the gap itself: "a host that reconnects buys a fresh session and a fresh cap" (`P2P_TRANSPORT_LAYER.md` § Clearnet reconnect throttle, registered 2026-10-09 and not built). Even once built, that throttle is per host, and step 1 makes hosts free.
- **The cost:** `GRAY_CAP` is 5000 (`lib.rs:120`), and 5000 ÷ 24 is about 210 short sessions. After that, every attacker admission evicts a uniformly random other gray seat (`evict_gray_over_cap`), so the attacker's share of gray rises towards 1 for as long as the feed runs. Honest inflow is bounded by honest disclosures: 12 per response, white only, and none below the floor.
- **The addresses can be live.** The same VPS answers on as many IPv6 addresses as it lists, so they pass our tests and are promoted to white like any honest peer. Honest nodes that dial them promote them too, and then disclose them to everyone (white-only disclosure is no barrier to a live attacker).

### Step 3: the attacker's share becomes our outbound set

- **Through churn.** Sessions end for ordinary reasons. Each refill is a uniform draw over white and gray, and confirm dials keep moving gray's composition into white. The attacker's share of our outbound set follows its share of the lists, which step 2 drives towards 1.
- **Through a restart, which is fastest.** Every restart reloads every address as gray, with no trust state saved (Rick, 2026-10-24). The address file holds the attacker's share as it stood at the last store. After a restart:
  - white is empty;
  - rule (a) keeps the first success;
  - below the diversity floor the fill confirms from gray until white holds 48;
  - every draw is at gray's attacker share.

  This is the Heilman restart vector, and our fresh-look rule is what makes it immediate. The compiled seeds also enter gray at each start, but as a handful of addresses among 5000.
- **The diversity floor doesn't help.** The floor counts addresses (48 in white). It does not count independent operators, and step 1 makes the count free.

### Step 4: inbound

The inbound ceiling is descriptor headroom (`InboundCeiling`, `shekyl-peer-policy`). An attacker with free hosts can fill it too, so every inbound slot is theirs as well. A per-host inbound limit doesn't bind for the same reason as step 1.

### What it costs the attacker

- **Resources:** one VPS with an IPv6 /64 and a script. No hashpower for the eclipse itself, only for a double-spend against the eclipsed node.
- **Time:** about 210 sessions to saturate gray, plus either the victim's next restart or ordinary churn to finish.

## 3. What already resists, and should be kept

- **No DNS seeds.** The compiled seeds are IPv4 literals (`shekyl-dialer/src/seeds.rs`), so there is no DNS poisoning at bootstrap.
- **No recency or last-seen weighting:** the draw is uniform (`candidate.rs:14`). Heilman's attack leaned on Bitcoin's preference for fresh timestamps, and we have no such bias.
- **White needs our own successful test.** Nobody can write white directly.
- **A received list is admitted or refused whole:** one foreign-connector entry, or the 25th address, refuses the whole list (D7, D-S1).
- **The gray cap with uniform eviction,** now including cooling seats (#1185): a bound on memory, though not on composition.
- **No misbehaviour is ever proven on clearnet.** An attacker cannot get honest addresses removed, only cooled.

## 4. On-path capture (needs a position)

| Position | Who holds it | Covers | Notes |
| --- | --- | --- | --- |
| LAN: ARP or neighbour spoofing, rogue DHCP, an evil-twin access point | anyone on the same segment | every path | cheap; laptops and phones on shared networks |
| Gateway or ISP | the access provider, a state | every path | cannot be stopped from blocking; the only goal is that it cannot impersonate (keyed listeners, a later round) |
| BGP interception of our peers' prefixes | a network operator, or a hijacker | the paths to those prefixes | Apostolaki et al.: nodes sit in a few hosting networks, so a few prefixes cover most paths; brief and globally visible |
| BGP interception of our own prefix | as above | our inbound | rarely all our paths |

Against NN, any of these can MITM every new clearnet session. A MITM is a malicious peer we did not choose. What it adds over logical capture is reach over sessions to honest peers, and plaintext.

## 5. Gaps, ranked by cost to the attacker

1. **A host is a /128.** Defining an IPv6 host as its /64 is identity, not diversity: it gives the per-host rules (draw, outbound, bans, intake, the future reconnect throttle) the meaning they already claim. This is separate from the withdrawn `/24` diversity question.
   - **Ruled for the accept-rate bound** (Rick, 2026-10-30; #1226).
   - **The other per-host rules move in this round's first PR:** the draw, outbound sessions, bans, intake and the reconnect throttle.
2. **Intake is reset by a reconnect.** Key it by source host (the group from item 1), not by session. This is the registered reconnect throttle with its unit corrected.
3. **The restart hands over the outbound set at gray's share.** This is in tension with the fresh-look ruling, and needs Rick. The choices:
   - keep fresh look, and rely on items 1, 2 and 4 to bound gray's composition;
   - persist a small anchor set across restarts (Bitcoin keeps its two last block-relay-only outbound peers). That is saved trust state, which the 2026-10-24 ruling refused.
4. **The floor counts addresses, not operators.** Group-aware diversity (/16, or an AS map) for the floor and the draw. This is D1/D2, withdrawn on 2026-10-11 with Tor available.
5. **On-path impersonation.** Keyed clearnet listeners, anchored by compiled seed keys. A separate design round; the false-key poisoning problem comes first.

Items 1 and 2 are cheap and make every later defence mean what it says. Item 3 decides whether a restart is an eclipse.

## 6. Open questions for Rick

- **IPv6 host unit:** a /64, or wider, such as Bitcoin's /32 for its groups? I suggest /64 for identity, and leaving wider grouping to the diversity question.
- **Intake by source:** should the cap become per source group, per 24 h, with a reconnect getting no fresh budget?
- **The restart:** does fresh look stand as ruled, with composition bounded by items 1, 2 and 4, or is a small anchor set acceptable?
- **Diversity:** reopen D1/D2 under the Tor-unavailable premise?
- **Measurement first:** a harness run of steps 1–3 against a node at `dev` (one IPv6 /64, scripted inbound feeds), so the attacker's share over time is measured, not argued.
