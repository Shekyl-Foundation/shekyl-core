# The Tor status crate (`shekyl-tor-status`)

**Status: OPEN** — design, round 1 (PR 2a). Rick's rulings of 2026-11-08,
2026-11-10, 2026-11-11 and 2026-11-12; the wire is `INPUT_GRAMMAR.md` §23 as amended by
Part G (§27–§28, IG-Q95…IG-Q101). PR 2b (#1347) wires it onto
`daemon_status` and the CLI.

## 1. What it is for

The Tor supervisor's status reaches the daemon's log today and nowhere else.
Operators need it over RPC, in `shekyl-cli` and in the GUI, and each of those
has to say the same thing the log says. This crate holds the one shape that
crosses the wire and the one function that turns it into words, so no
consumer writes a sentence of its own (`TSR-Q13`; Rick, 2026-11-08).

## 2. Rules

- **No I/O, no async, no clock.** Its only dependency is `serde` with
  `derive`. The daemon, `shekyl-tor-control-client`, `shekyl-rpc-types` and
  `shekyl-cli` depend on it; it depends on none of them.
- **The wire carries exactly what the renderer reads** (Part G). A fact the
  renderer does not speak from stays in the daemon's log
  (`stuck_upload_rounds`, IG-F28). A fact the renderer speaks from has a field.
- **Time on the wire is an age or a reading's figure.** Every duration
  crosses as whole seconds of awake time, and no reading of any clock
  crosses (IG-Q93, IG-Q96). The ages, `tor.age`, `tor.onion.age` and
  `tor_quiet`'s `failing.age`, are taken at the ask. The bootstrap's
  `unchanged` and `window` are not ages: with `download` they are one
  reading, taken at the last sample, and cross as they were taken (Rick,
  2026-11-12).
- **No daemon-authored free text.** Every value is a keyword, a number or a
  switch. The file a refused pin names, and its reason, stay in the
  daemon's log (Rick, 2026-11-12; IG-F26); the data directory's path is the
  caller's, under `config` (IG-Q97).
- **Values, never sentences.** The daemon sends the typed status; each client
  renders it with this crate. A translation, when there is one, lives here.
- **An unknown variant decodes.** Every closed set on the wire has an
  `Unknown { tag }` arm. An older client meeting a newer daemon's keyword
  decodes the rest of the reply and renders that one value as "The node
  reports a Tor condition this version does not know. Update this program."
  once, however many values it did not know (rule 82). The keyword sets'
  decoders come from one macro; each one-key object's decoder is written by
  hand, since serde's `other` attribute takes no payload and keeps no tag.
  An unknown key's payload is skipped; a second key is refused.
- **An unknown value fails closed** (Rick, 2026-11-12). The send flow reads
  one accessor, `TorStatus::own_tx_hides_address`, and it is true only for a
  `tor` setting of `managed` or `operator` together with the origination
  `address-hiding`. An unknown origination, or an unknown `tor` or `clearnet`
  setting, is not address-hiding, so the send flow holds the transaction.
  No other accessor answers that question.

## 3. The shape

The crate's types are §23's, under §23's names; the supervisor's own types
stay in `shekyl-tor-control-client` and are not on the wire.

`TorStatus`, the Status level's Tor fields of `daemon_status`, under every
`tor` setting:

| Field | Type | From |
|---|---|---|
| `posture` | `{tor: managed \| operator \| off, clearnet: on \| off}` | the settings |
| `origination` | `address-hiding \| connecting \| rebuilding \| clearnet-only \| offline` | the relay's verdict and the settings (`OwnTx`, with `Held` split by the verdict) |
| `sync_connector` | list of `clearnet \| tor` | the sessions |
| `tor_quiet` | null, `{empty}`, `{failing: {age}}` | the dialer's census (`TorQuiet`) |
| `tor` | `ManagedTor` or null; null unless `posture.tor` is `managed` | the supervisor's core |

`ManagedTor`: `state`, `cause`, `age`, `respawn_count`, `progress`, `flagged`,
`fix`, `onion`, `bootstrap`, `carriage`, with the keys and payloads §23 and
Part G rule. `hiding`, Health's boolean, is the relay's verdict and is not in
this crate: it is a plain switch on the reply and nothing renders it.

## 4. The renderer

`render(&TorStatus, data_dir: Option<&str>) -> String` is the supervisor's
renderer moved and made to read the wire shape. `data_dir` is the path
`unusable` names, passed only by a caller that holds the `config` grant
(IG-Q97); without it the sentence says "Tor's data directory". The daemon's
log always passes it (Rick, 2026-11-12), so the supervisor's
`Cause::DirectoryUnusable` carries no path.

`install_sentence` and `held_at_start_sentence` are public beside it: the
daemon's pin warning speaks them, from the same table.

Two cases the log never had to say, because no supervisor ran there:

- **An operator's Tor** (`tor` null, Tor on): the first sentence comes from
  `origination` alone (Rick, 2026-11-12). `address-hiding` says Tor carries
  the node's traffic; `connecting` and `rebuilding` say the node holds its
  own transactions, with what it syncs over. No managed fix is offered,
  since there is no `tor` object to carry one.
- **Tor off:** `clearnet-only` and `offline` say what they say today.

## 5. The snapshot

`shekyl-tor-control-client` turns the core's `Status` into a `TorStatus` at
the moment it is asked: `snapshot(&Status, Connectors, now) -> TorStatus`,
and `Core::view(now)` for the core's own. It holds the clock readings
(`since`, the onion's `since` while publishing and while unreachable,
`evidence_at` while reachable, and the quiet span's start) and subtracts
them from `now`, on the awake clock the supervisor already runs on.
`Inbound::Publishing` carries the time publishing began so that the onion's
age has a start in every state, and `TorQuiet::Unanswered` carries when the
held span began, not its length at the supervisor's last look.

`progress` is the last bootstrap percent whenever the bootstrap is spoken,
and null otherwise (§23 as amended 2026-11-12): while `state` is
`bootstrapping`, and while a bootstrap reading stands, which happens only
while Tor is bootstrapping, so an `impaired` bootstrap also carries its
percent. The snapshot is the one place that rule lives. The renderer speaks
the bootstrap exactly when `progress` is non-null and has no rule of its
own, so a null never prints as 0% (RK-D23).

The pin's refusal carries no file: `install-defect` is null. The daemon
logs the file and the reason at the start, and at every running re-check
that refuses (`Drive::pin`).

The daemon's own log line is `render(&core.view(now), Some(data_dir))`, so
the log and every client say one thing. The supervisor's renderer is deleted
with the move.

## 6. Tests

1. **Round trip, exhaustive:** a table built by a `match` over every variant
   of every set on the wire (adding a variant without a row does not
   compile); for each, `decode(encode(s)) == s` and
   `render(decode(encode(s))) == render(s)`.
2. **Unknown variants:** a reply carrying a keyword this build does not know,
   in each set, decodes, and renders the update sentence; every other field
   is intact.
3. **The log is the renderer:** the supervisor's render tests, which pin
   its sentences, run through `render(&core.view(..))` with their expected
   text unchanged, except the space-shortfall test, which finds the path the
   caller passes.
4. **Fail closed:** a reply carrying an unknown origination keyword, and one
   carrying an unknown `tor` or `clearnet` setting, never reads as
   address-hiding through `own_tx_hides_address`, and renders the update
   sentence.
5. **An operator's Tor:** `tor` null speaks from the origination alone and
   offers no managed fix.
6. **The path:** `unusable` names the directory only when the caller passes
   it.
7. **Ages:** a status read twice, 10 s apart, reports `tor.age`, the
   onion's age and `tor_quiet`'s `failing.age` 10 s larger, the onion in
   each state that has an age.
8. **No percent without a sample:** a status with `state` bootstrapping
   and `progress` null prints no percent; an `impaired` bootstrap with
   `progress` 0 prints 0%.
9. **The refused file is in the log:** a running re-check's refusal logs
   one warning naming the file and the reason; the first pin's, which the
   start announces, is not said again.

Each test names the edit that makes it fail.

## 7. Not here

The wire placement (`daemon_status`, its grant levels, the RPC minor),
the CLI, oracle vectors and the Pi run are PR 2b's.
