# Brief A1: the step 7 evaluation record (the Noise flip, phase A)

**Status:** BRIEF, revision 2 (2026-10-30): a lane's instructions for phase A of the Noise flip, not a design record.
**Revision 2, 2026-10-30.** It replaces revision 1. Item 6's bound is ruled as its own PR (Rick, 2026-10-30).
**For:** the transport lane. This brief produces evidence and recommendations. It builds nothing that ships.
**Read at:** `dev` `dc2a617d22`. Re-read every anchor at your own pin.

## The order of work (Rick, 2026-10-30)

| Phase | What | Notes |
| --- | --- | --- |
| A | Evidence, with `dev-clearnet-encrypt` still in place | This brief is A1 |
| B | The framing PR | Implements A1's ruled decisions |
| C | The rehearsal on the final wire | `claude/NOISE_FLIP_REHEARSAL_BRIEF.md` |
| D | The flip | A rule 07 flag day |

The rest of phase A belongs to other briefs:

| Item | What |
| --- | --- |
| A2 | Fuzz campaigns |
| A3 | Independent cross-check of `NNhfs` |
| A4 | ProVerif extension |
| A5 | The plaintext control, folded into this brief as item 10 |
| A6 | The stale-node warning |

There is one flag day, and every rehearsal measurement runs on the wire that ships.

## Why step 7 decides the wire

`P2P_TRANSPORT_LAYER.md`:
- **Step table, row 7:** "Option evaluation: window size, rekey cost, Nagle, flood". The flip is "only after step 7".
- **D14 item 4:** framing is fixed-window. The window size is derived from the measured message-size distribution, and the flush policy "is measured in step 7 with the window size and Nagle". "The PWD-T8 vectors are re-minted when the window size is derived" (also `SHEKYL_P2P_PROTOCOL.md:3423`). Every-record rekey and the window size are decided together.
- **Today's wire is the interim framer** (`shekyl-p2p-transport/src/channel.rs`): an encrypted 2-byte length, then the body, BOLT-8 style. It hides the length field but leaves each burst's size visible.

A1's output is a set of recommendations. Each is marked "for Rick's ruling", and B implements what he rules.

## What to measure and decide

Use the floor device (rule 76) and roles, not hosts (rule 37). Claim every host in the usage ledger first (rule 38).

1. **The message-size distribution** (the input to item 2).
   - On the fleet, with the switch on, record each Levin message's size, direction and send time. Record nothing else: no content, no peer address, and no command name beyond its class.
   - Record at least 24 h of ordinary traffic, plus one full initial sync.
   - Use a measurement build (`measurement-spans`), never the shipped binary.
2. **The window size W.**
   - For each candidate W, report:
     - padding overhead over the distribution;
     - windows per message, which is what an observer sees;
     - seal and open cost per window on the Pi.
   - State the objective you optimise, for example the overhead allowed at the Pi floor against size resolution, and show the trade-off curve.
   - Recommend one W.
3. **The flush policy.**
   - Measure the options: seal each window at once, or wait up to T for more bytes, at several values of T.
   - For each, report:
     - the added latency on Dandelion++ stem and fluff relay, and on block relay;
     - what an observer learns from window boundaries and timing.
   - Recommend a policy.
4. **Nagle.**
   - Test on and off, crossed with each flush policy from item 3.
   - Capture the on-wire segment sizes from the far side.
   - Recommend a setting (D3's row: "measure before deciding").
5. **Rekey.**
   - Measure three HMAC-BLAKE2s per record against sealing one window at the recommended W, on the Pi. C5 measured one rekey at 5.06 µs; its 65,535-byte seal ratio is not the decision.
   - If the cost is affordable, recommend every-record rekey. Otherwise, derive an interval from the measured record rates (D14 item 4).
   - **Formal check:** build the FOLLOWUPS ProVerif extension with this item (`FOLLOWUPS.md:233`; #1025 has landed). It has two parts:
     - the rekey ratchet's forward secrecy, as a leak-at-epoch-*j* query, pinned holding, with an edit pinned failing;
     - responder-side network binding, as a stated non-property.
6. **Flood.**
   - **The gap.** The accept-rate bound D10.3 assigns to this layer is not built. `shekyl-transport-layer/src/admission.rs` has the occupancy ceiling and bans only. Today a flood of message 1s is limited only by the blocking pool's cap.
   - **The CPU budget.** Propose, for Rick's ruling, the share of a Pi core that inbound handshakes may take. D10.3 says no rate is written before that budget.
   - **The values.** Derive the per-connector and per-host accept rates from the responder cost: 684.5 µs per handshake (C5), about 1,460 per second per core.
     - An IPv6 host is its /64, the unit the eclipse threat model's item 1 adopts (`claude/CLEARNET_ECLIPSE_THREAT_MODEL.md`).
     - Whether to aggregate hosts further is a measured question (D10.3).
   - **The measurement.** Under a message-1 flood, measure honest-session service in two configurations:
     - today, with only the blocking cap;
     - with the derived bound applied in a measurement build.
   - **Ruled (Rick, 2026-10-30):** the bound is built as its own PR before phase C. It is not part of the framing PR.
     - **The mechanism** can be built now: a bound at accept, before any cryptographic work, per connector and per host, with an IPv6 host being its /64.
     - **The values** come only from A1's ruled table, and the PR merges only after that ruling (D10.3: no rate is written before the budget).
     - **The rates are protocol data,** held with the connector's data beside its declaration, the same on every node (rule 71).
7. **Failures before the channel exists** (D10.2). For every pre-channel failure path, capture from the far side what each sends:
   - zero bytes written;
   - FIN, never RST;
   - no linger.

   Record the timing per cause. A timeout cannot match an immediate refusal in timing, so state which causes can be told apart by timing and say whether that leaks anything.
8. **DSCP** (D14 item 6). Record the Type of Service byte as it leaves the host, with no `setsockopt`, on Linux, Windows and macOS.
9. **The extra round trip.**
   - Measure dial-to-session time with the option on and off, on the LAN, New York and South America legs, with the Pi at each end.
   - This is the plaintext control for the clearnet deadlines.
10. **The plaintext control** (A5). On the Pi, record an initial sync over plaintext and over Noise: wall time, CPU, and bytes on the wire. It can never be taken after the flip.

## Output

- **One evaluation record** in `docs/benchmarks/`, with every measured row in §97 by role and date.
- **A decisions table**, each row marked for Rick's ruling: W, the flush policy, Nagle, the rekey interval, the CPU budget, and the accept-rate values.
- **B starts from the ruled table.**

## Out of scope

- building the framing (B);
- building the accept-rate bound (its own PR, as ruled);
- the fuzz campaigns (A2) and the cross-check (A3);
- the stale-node warning (A6).

No push without Rick's go-ahead.
