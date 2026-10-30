# Brief C: the rehearsal on the final wire (the Noise flip, phase C)

**Status:** not started. Phase C runs after A and B.

**Revision 2, 2026-10-30.** It replaces revision 1. The accept-rate bound and the soak period are ruled (Rick, 2026-10-30).
**For:** the transport lane, with the dialer lane for the K and S follow-up (C4) and the refusal cells.
**Read at:** `dev` `dc2a617d22`. Re-read every anchor at your own pin.
**Order (Rick, 2026-10-30):**
1. A: evidence;
2. B: the framing PR;
3. C: this rehearsal;
4. D: the flip, a rule 07 flag day and one wipe release.

## Prerequisites (each merged or shipped before C starts)

- **A1 ruled** (`claude/NOISE_STEP7_EVALUATION_BRIEF.md`): W, the flush policy, Nagle, the rekey interval, the CPU budget, and the accept-rate values.
- **B merged.** It carries:
  - fixed windows with the authenticated occupancy;
  - the ruled flush policy and rekey;
  - the PWD-T8 vectors, re-minted;
  - a fuzz target for the new record decoder;
  - the cross-check (A3) updated to the new framing.

  The option `dev-clearnet-encrypt` still exists.
- **The accept-rate bound merged,** as its own PR (Rick, 2026-10-30; A1 item 6). It is keyed per connector and per host, with an IPv6 host being its /64, and its values come from A1's ruled table.
- **The stale-node warning (A6) shipped one release before D**, hardened as Rick ruled (2026-10-30):
  - it fires only on a well-formed first Noise message (exact prefix and length), from several distinct peers;
  - it is logged once at warning level, then rate-limited;
  - it points only to the official release channel, never to anything a peer sent.

## The rehearsal

1. **Deploy B to the whole testnet fleet** with the switch on, for 7 days (Rick, 2026-10-30).
   - A no-go may be called at 72 h at the earliest, and only on a registered prediction that has failed. Otherwise the soak runs the full 7 days.
   - Add the floor device, a Windows node and a macOS node. First confirm in the usage ledger which of those hosts run fleet daemons, and claim them (rule 38).
2. **Register predictions before the soak**, each with a pass band, in the same record:
   - session churn per connector;
   - gap timeouts by cause;
   - handshake CPU and steady-state CPU on the Pi;
   - bytes per dial;
   - per-session overhead against the plaintext control (A1 item 10);
   - Dandelion++ stem and fluff latency against the control.

   A result outside its band is a finding, not a retune.
3. **The link budget.**
   - Test that the operator link budget counts wire bytes, padding and Noise overhead included. `P2P_TRANSPORT_LAYER.md`'s rate-limit table says it must once the flip lands.
   - Show it on one capped node.
4. **Re-derive the clearnet deadlines on the final wire.**
   - Dial, handshake and gap (`spans.rs`: 1.415 s, 1.426 s, 1.430 s) were derived from the 2026-09-29 cross-build, with the option off.
   - Re-measure on the LAN, New York and South America legs, with the Pi at each end, using D9's method.
   - The quiet span S follows on its own: it is derived from the dial profile's deadline.
   - **C4, the dialer lane:** re-derive K only if clearnet's live-dial failure rate leaves the band registered in item 2. The source is the fleet's clearnet live-dial outcomes, as §97 names it.
5. **Final fuzz campaigns on the flip head.**
   - Targets: `fuzz_read_message1`, `fuzz_read_message2`, `fuzz_open_one`, `fuzz_classed_opener`, and B's record decoder.
   - Each is time-boxed with its duration stated; record the corpus.
   - The CI step only checks that the harness files exist, so these runs are the evidence.
6. **The refusal cells, with the dialer lane.** Run a node on the release with the warning against the rehearsal fleet, in both directions. For each, register the prediction and record:
   - one typed cause on each side (`PrefixMismatch`), with no marks;
   - no ban, and no misbehaviour;
   - the address cools, as for any failed test;
   - the warning fires only under its conditions;
   - a malformed prefix from one peer does not fire it.

## Exit

- **A rehearsal record** with pass or fail against every registered prediction, the re-derived deadlines in §97, and the fuzz durations and corpora.
- **The go or no-go for D is Rick's,** made from that record.

## Not this brief

D itself is the agent's flip PR. Its contents, as ruled:
- **Delete:**
  - the option, its config row, its `INPUT_GRAMMAR.md` row, and the "encrypt" glossary term;
  - the generated option docs;
  - the flag in the BA-T5 bench scripts;
  - ruling 4's exception text;
  - the `tor = off` wording at `TOR_SUPERVISOR.md:147`.
- **Change the code:**
  - delete `ClearnetOption` and its `Off` arm;
  - rename `Choice::Plain` to say "no added layer, the network encrypts" (for example `Native`), keeping its native-encryption arm, which the Tor column's test exercises;
  - add a test that the clearnet column cannot produce it.
- **Convert the tests:** the plaintext test pairs move to Noise.
- **Release:** one wipe release, with the testnet genesis rotated.
- **Runbook:** stop everything, upgrade, start, then confirm that only encrypted clearnet sessions exist.

No push without Rick's go-ahead.
