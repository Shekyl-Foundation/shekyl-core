# The Tor status crate (`shekyl-tor-status`)

**Status: OPEN** — design, round 1 (PR 2a). Rick's rulings of 2026-11-08,
2026-11-10 and 2026-11-11; the wire is `INPUT_GRAMMAR.md` §23 as amended by
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
- **Time on the wire is an age.** Every duration crosses as whole seconds of
  awake time: `tor.age`, `tor.onion.age`, the bootstrap's `unchanged` and
  `window`, `tor_quiet`'s `failing.age` (IG-Q93, IG-Q96). No reading of any
  clock crosses.
- **Values, never sentences.** The daemon sends the typed status; each client
  renders it with this crate. A translation, when there is one, lives here.
- **An unknown variant decodes.** Every closed set on the wire has an
  `Unknown { tag }` arm. An older client meeting a newer daemon's keyword
  decodes the rest of the reply and renders that one value as "The node
  reports a Tor condition this version does not know. Update it." (rule 82).
  The decoder is written by hand for each externally tagged set, since
  serde's `other` attribute takes no payload and keeps no tag.

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

`render(&TorStatus, data_dir: Option<&str>) -> String` is today's
`posture::render` moved and made to read the wire shape. `data_dir` is the
path `unusable` names, passed only by a caller that holds the `config` grant
(IG-Q97); without it the sentence says "Tor's data directory".

Two cases the log never had to say, because no supervisor ran there:

- **An operator's Tor** (`tor` null, Tor on): the behaviour sentence comes
  from `origination` alone. `address-hiding` says Tor carries the node's
  traffic; `connecting` and `rebuilding` say the node holds its own
  transactions, with what it syncs over.
- **Tor off:** `clearnet-only` and `offline` say what they say today.

## 5. The snapshot

`shekyl-tor-control-client` turns the core's `Status` into a `TorStatus` at
the moment it is asked: `snapshot(&Status, posture, now) -> TorStatus`. It
holds the clock readings (`since`, the onion's `since` and `evidence_at`) and
subtracts them from `now`, the network's monotonic clock that the supervisor
already runs on. One function, tested on `ManualClock`: a status read twice,
10 s apart, reports every age 10 s larger.

The daemon's own log line is `render(&snapshot(..))` from this PR on, so the
log and every client say one thing, and `posture::render` is deleted with the
move.

## 6. Tests

1. **Round trip, exhaustive:** a table built by a `match` over every variant
   of every set on the wire (adding a variant without a row does not
   compile); for each, `decode(encode(s)) == s` and
   `render(decode(encode(s))) == render(s)`.
2. **Unknown variants:** a reply carrying a keyword this build does not know,
   in each set, decodes, and renders the update sentence; every other field
   is intact.
3. **The log is the renderer:** the supervisor's render tests, which pin
   today's sentences, run through `render(&snapshot(..))` unchanged in their
   expected text.
4. **Ages:** the snapshot on `ManualClock`, as §5.

Each test names the edit that makes it fail.

## 7. Not here

The wire placement (`daemon_status`, its grant levels, the RPC minor),
the CLI, oracle vectors and the Pi run are PR 2b's.
