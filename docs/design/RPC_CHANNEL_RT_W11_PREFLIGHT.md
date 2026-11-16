# RT-W11 — the channel's clients and the tunnel: rule-26 pre-flight

**Status:** Round 0 pre-flight. **RT-W11 authorized 2026-11-15** (Rick),
one pull request off `dev`. The first rulings on its scope were given the
same day and are recorded in §2. The substrate re-check is recorded (§3).
The questions in §4 are **open**: `IG-Q108`…`IG-Q111` (the names the
tunnel and a CLI on another host read) and `RT-O37` (the reserved slots).
What was and was not executed is §3.10. The parts of §5 that no open
question touches proceed once §3.10's runs are recorded; the parts that
read an open question's answer wait for it.
**Ground:** `shekyl-core` `dev` **`bc3df402f4`**. Every `file:line` below
was read at that commit.
**Parent:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md) (round R1, ruled
2026-10-09) §4.3, §4.5, §5, §6.2, §6.3, §8 and the RT-W11 row of §13;
the RT-W10 pre-flight ([`RPC_CHANNEL_RT_W10_PREFLIGHT.md`](RPC_CHANNEL_RT_W10_PREFLIGHT.md));
[`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) IG-Q31, IG-Q87, IG-Q88 and §12.1.
**Family:** `RT-` (registered). This document mints **RT-O37** and
**RT-P10** inside it, and the grammar's family mints **IG-Q108…IG-Q111**
here, to be moved into `INPUT_GRAMMAR.md` when ruled.
**Decision authority:** Rick.

---

## 1. What RT-W11 is, and is not

RT-W11 is the channel's client side. It builds three things, one pull
request (Rick, 2026-11-15):

- **The channel initiator** in `shekyl-rpc-transport`: it dials a
  daemon, runs the `hybridXK` handshake against the daemon's public
  bundle, and carries the record stream, behind the same calls the
  transport's other targets offer (`call`, `json_rpc`, and the async
  `Rpc` trait).
- **`shekyl-cli`'s enrolment words** (IG-Q87): `rpc client add`, `set`,
  `remove`, `list` and `rpc bundle show`.
- **`shekyl-rpc-tunnel`** as `RPC_CHANNEL.md` §8 rules it, with its
  session pool.

It is not:

- **RT-W12.** No client moves to the channel by default. The engine's
  daemon client, `shekyl-wallet-rpc`, the GUI and the mobile wallet keep
  their legs; the plaintext admin listener stays, and so does the
  daemon client's `https://` arm.
- **RT-W10 step 5.** The CLI's other words do not move onto the owner's
  leg here. Only the five enrolment words reach the daemon through
  `LocalTarget`, because the plaintext listeners do not serve them (§5).
- **RT-W14.** Service mode's installer, its enrol-at-install and the
  Windows service directory's creation stay there.

---

## 2. Rulings given with the authorization (Rick, 2026-11-15)

1. **Placement.** The initiator goes in `shekyl-rpc-transport`, beside
   `LocalTarget`, behind the same calls. Step 4's test-only handshake
   client moves onto it.
2. **The CLI's legs.** On a service host the CLI finds the service's
   rendezvous record and console key itself, from the fixed paths
   `shekyl-daemon-config` already holds (§4.5's console-key row assumes
   this), and never keeps a second copy of those paths. A run-as-me owner
   enrols over `LocalTarget`. `daemon-bundle-file` and `rpc-key-file` are
   for a CLI on another host, and are posed with the tunnel's table.
3. **The grammar.** The tunnel's table is posed as IG questions here. It
   is one table shared with the CLI's channel rows, so each name means the
   same thing in both, and it reuses existing names where they fit. The
   tunnel's listener is loopback-only, never a wildcard (RT-14).
4. **A per-client cap.** `SESSIONS_PER_CLIENT = 4` in
   `shekyl-rpc-channel`, an Assumption whose basis is that at a full pool
   five clients and the console fit in 25 (`rpc-connections-max`'s
   default). The daemon refuses a fingerprint's next session past it with
   a typed refusal, and the tunnel's pool uses the same constant. The
   reason: the session index has no cap per fingerprint (§3.3), so one
   compromised enrolled key, such as the website's internet-facing tunnel,
   could take every slot.
5. **The pool.** It opens sessions on demand and keeps one open. A
   request beyond the cap waits for a session, bounded by the 11 s
   handshake deadline. Extra sessions close after a short idle.
6. **Reserved slots.** Show that the owner's socket and the console
   session cannot be crowded out of `rpc-connections-max`; if they can,
   give them reserved slots. §3.4 shows that they can; §4, RT-O37, poses
   the mechanism.
7. **Idle.** The daemon's channel idle stays one hour; "until RT-W11 sets
   it" goes from §6.3. The tunnel reopens its kept-open session when the
   daemon closes it.
8. **A probe.** Measuring the pool size under load is registered as a
   probe (RT-P10, §6); it does not block this pull request.
9. **RT-P5.** The 4.x size measurement is its own registration and pull
   request ([`rt_p5_rpc_message_sizes_20261115.md`](../benchmarks/rt_p5_rpc_message_sizes_20261115.md)),
   not this one. RT-W11 pads to whatever RT-O6 rules.

---

## 3. Substrate re-check

### 3.1 The handshake client that exists

The only client of the channel is test code. `shekyl-daemon-rpc`'s
`channel/tests.rs:175-237` (`open_stream`, `connect`, `Session::call`)
dials, runs the handshake, wraps the stream in hyper's
`client::conn::http1` and posts JSON-RPC. `shekyl-daemon`'s
`tests/service_rendezvous.rs` does the same through the service record. Neither applies the
client's side of §4.3: no deadline, no retry after a timeout, no back-off
after busy, no typed failure. The pieces exist in `shekyl-rpc-channel`:
`handshake::Client` (`handshake.rs:250-500`), the busy reply's check
(`ClientAwaitingMessage2::is_busy`), `deadline::HANDSHAKE_DEADLINE` (11 s,
`deadline.rs:32`) and `retry::HandshakeRetry` (`retry.rs:76-130`), which
decides and reads no clock. The record stream and the submission mark are
`shekyl-rpc-stream`'s (`RecordStream`, `submission_mark`).

### 3.2 The transport crate's targets

`shekyl-rpc-transport` holds `HttpRpc` (the async `Rpc`), `SyncDaemon`
(`lib.rs:612-700`: one current-thread runtime per client, refused inside
a runtime) and `LocalTarget` (`local.rs:132-260`: sync, one connection
per call, a typed `LocalFault`). The three share `call_via` and
`json_rpc_via` (`lib.rs:697`, `lib.rs:718`), the envelope, the reply's shape check
and the refusal's reading. The crate already depends on tokio and hyper's
HTTP/1 client. It does not depend on `shekyl-rpc-channel`,
`shekyl-rpc-stream` or `shekyl-rpc-grants`; RT-W11 adds those three.
Its dependents are `shekyl-cli`, `shekyl-engine-core`'s callers and the
GUI (`shekyl-gui-wallet/src-tauri/Cargo.toml`), which RT-W12 moves onto
the channel.

### 3.3 The daemon's session index has no per-client cap

`channel/sessions.rs` indexes live sessions by fingerprint. `register`
(`sessions.rs:88-107`) adds a session under the index's lock if the
enrolment still admits it, with no count. The listener registers after
the first record opens (`listener.rs:131-143`, the call at 135), so by then the session is
authenticated and the daemon can answer it: a refusal at registration
can be a typed JSON-RPC error on the first request rather than a silent
close.

### 3.4 The owner's socket and the console can be crowded out

One `ConnTracker` admits every connection the daemon serves
(`conn_limit.rs:126-215`): the plaintext admin and view listeners, the
owner's socket and the channel listener all pass through it
(`server.rs`, `serve_bound`). The owner's socket and pipe are admitted as
loopback (`conn_limit.rs:286-306`). The daemon builds the limits with one
total and no per-address cap (`run.rs:160`,
`ConnLimits::checked(connections_max, 0, 0)`). A connection is admitted
at accept, before anything about it is known, and is counted until it
closes. So:

- **The owner's socket can be crowded out.** Twenty-five connections
  held by anything else (plaintext loopback callers, channel strangers in
  their handshake, enrolled clients' sessions) refuse the owner's next
  connection at accept. Until RT-W12 the plaintext view listener is
  reachable by any local account, so any local account can do this.
- **The console can be crowded out,** in the same way, and also by
  enrolled clients alone: with the cap, five full pools hold twenty of
  the twenty-five, and the other five are shared with every caller above.
- **Anyone who can reach the channel listener can hold slots, without
  the bundle.** A connection that sends nothing holds its slot until the
  message-1 deadline, 4 s (`listener.rs`, `MESSAGE1_DEADLINE`; step 4's
  test `a_silent_connection_is_closed_at_the_message_1_deadline`), and can
  be opened again at once. A message 1 that fails mac1 closes at once, but
  silence is cheaper. With the bundle, the whole-handshake deadline (11 s)
  bounds a stall after message 2.

So both need reserved slots (§4, RT-O37).

### 3.5 Owner-only files

The channel's file handling is `shekyl-daemon-rpc`'s:
`channel/files.rs` (`read_key`, `write_private`, `replace_private`,
`private_store`) and `channel/stage.rs` (created `0600` with `O_EXCL` on
Unix, the mode set exactly afterwards; on Windows created owner-only with
the no-read-up label in the creating call through `shekyl-win-sec`'s
`create_rendezvous_file`), and the staged write's durability is
`shekyl-daemon-config`'s `marker::sync_dir`. The key file's bytes are
`shekyl-rpc-channel`'s (`StaticKeypair::to_key_file`, `from_key_file`,
`identity.rs:97-170`). The tunnel and a CLI on another host need the same
two acts for their own key, so the file half moves to a crate both can
reach. `shekyl-os-account` is the leaf that already holds this machine's
account reads on both platforms (libc on Unix, `shekyl-win-sec` on
Windows), and `shekyl-rpc-transport` already depends on it. The
owner-only file helpers move there with `sync_dir`;
`shekyl-daemon-config`, which does not depend on it today, gains the
edge to that leaf and its `marker` reads `sync_dir` from it;
`shekyl-daemon-rpc` reads the helpers from it. No copy is kept.

### 3.6 The fixed service paths

The service's data home is `shekyl-daemon-config`'s
(`paths.rs:34`, `SERVICE_DATA_HOME`, under `shekyl-process`'s
`fixed_service_parent`); its rendezvous directory is
`shekyl-process::service_rendezvous` and `shekyl-daemon-config`'s
`owner_socket::service_rendezvous`; the record's name is
`shekyl-rpc-rendezvous`'s (`service_file_name` over `rendezvous_name`)
and its form `ServiceRecord`; the console key's file name is
`shekyl-daemon-rpc`'s `CONSOLE_KEY_FILE` (`channel/files.rs:31`). The
daemon composes the record's path in `channel/rendezvous.rs:36`
(`record_path`). The CLI depends on all four crates already
(`shekyl-cli/Cargo.toml`). It reads each path through these functions;
`record_path` moves to `shekyl-rpc-rendezvous` so the daemon and the
CLI call one function.

### 3.7 The idle

`shekyl-rpc-stream`'s `RECORD_IDLE` is one hour (`lib.rs:92`). Its doc
says RT-W11's pool replaces it; Rick ruled it stays (§2, item 7). The
doc changes with §6.3's sentence.

### 3.8 The grammar

`INPUT_GRAMMAR.md` has no table for `shekyl-rpc-tunnel` and no row for a
channel client: §12.1's daemon rows are `daemon-endpoint` (peer-endpoint,
IG-Q31), `daemon-socket-file` (the owner's leg) and `daemon-socks`. The
glossary's `listen` is "a local endpoint a listener binds", with
`clearnet`, `onion`, `rpc`, `view` and `admin` as its parents. §6.2 rules
the default request: the `view` preset.

### 3.9 The CLI's words

`shekyl-cli`'s words are a hand-written catalog (`catalog.rs`); the
operator's words (`ban …`) are in `console/operator.rs`. There is no
`rpc` word. Every console word today reaches the daemon through
`SyncDaemon` at `daemon-endpoint`.

### 3.10 What was and was not executed

- **Step 4's channel tests at the ground** (`shekyl-daemon-rpc`'s
  `channel::tests`, `shekyl-daemon`'s `service_rendezvous` and
  `owner_socket`): to be run on a fleet host before the first production
  commit, and recorded here.
- **The dependency gates the initiator's edge reaches.** Adding
  `shekyl-rpc-channel` under `shekyl-rpc-transport` puts the handshake,
  and with it ML-KEM decapsulation, into the graphs of `shekyl-cli`,
  `shekyl-wallet-rpc`, `shekyl-engine-core`'s callers and the GUI. The
  gates that read those graphs are `check_rt_p4_standing.py` (the
  `fips203` closure and the build's flags), `check_clatter_not_in_production.py`,
  `check_p_fetch_dep_cut.py`, `check_bench_not_a_dependency.py` and the
  GUI pin job. They run in step 5, when the edge exists, and are recorded
  there. Not executed here: there is no edge to read yet.

---

## 4. The questions

Each states the problem, then the question, then a recommendation.

### IG-Q108 — the channel client's rows

**Problem.** The tunnel always speaks the channel. A CLI on another host
speaks it when told to. Both need the daemon's address, the daemon's
public bundle, this client's key, and the grant it asks for (§6.2).
Rick ruled one table for both, with existing names where they fit.

**Question.** The rows, their kinds and defaults.

**Recommended.**

| Name | Kind | Default | Binaries | Notes |
|---|---|---|---|---|
| `daemon-endpoint` | peer-endpoint | the CLI: as §12.1; the tunnel: required | both | Reused: the daemon's address, an IP or an onion (IG-Q31). With `daemon-bundle-file` set, the CLI dials it over the channel |
| `daemon-socks` | endpoint | unset | both | Reused: SOCKS5, for an onion |
| `daemon-bundle-file` | path | the tunnel: required; the CLI: unset | both | The daemon's public bundle, as `rpc bundle show` prints it. Set, it selects the channel. Unconstructible with `daemon-socket-file` |
| `rpc-key-file` | path | the account root + `rpc-<binary>-<network>.key` | both | This client's static key. A file anyone else can read is refused with a typed code, never repaired (as `wallet-password-file`) |
| `rpc-request` | a list of grant and preset keywords | `view` (§6.2) | the tunnel | The grant the tunnel's pool asks for in message 3, one grant per pool (§8). The connection holds it clamped to the ceiling; the tunnel reports what it received (§6.2, §4.5) |

`client` and `bundle` already have one meaning under `rpc` (IG-Q87), and
`key` gains one: "this client's static key". `request` under `rpc` is
"the grant a client asks for".

**What the CLI asks for, and which of its words these rows move.** The
CLI does not read `rpc-request`. Each word asks for exactly the grant its
method's row needs (`rpc client add` asks for `enrol`), so a CLI never
holds a grant it is not using. The console key asks the same way: it
holds every grant, and asks for the word's. In RT-W11, `daemon-bundle-file`
and `rpc-key-file` move **only the five enrolment words** onto the
channel. Every other console word, and the wallet session's daemon leg,
stay where they are until RT-W12 moves them (§1).

### IG-Q109 — making a client's key and showing its fingerprint

**Problem.** §5: each endpoint generates its own bundle; the tunnel
"generates and holds that host's static bundle; prints its fingerprint
for enrolment" (§8). The operator then enrols that fingerprint with
`rpc client add`. A CLI on another host needs the same.

**Question.** How a key is made, and how its fingerprint is shown.

**Recommended.** A key is made only when asked, never as a side effect
of a dial: a dial with no key file fails, naming the word that makes one.
On `shekyl-cli`, the words `rpc key create` (refused if the file exists;
prints the fingerprint) and `rpc key show` (prints the fingerprint). On
`shekyl-rpc-tunnel`, which has no command words, the one-shot switches
`rpc-key-create` and `rpc-key-show`, the shape `rpc-console-key-reset`
already has on `shekyld` (IG-Q88): each does its act and exits. The
fingerprint prints as `rpc client list` shows one, so the operator pastes
it unchanged.

### IG-Q110 — the tunnel's listener

**Problem.** §8: the tunnel listens on the consumer's host, loopback
only, through the listen classifier (RT-14: a specific address, never a
wildcard), and offers a socket where the consumer can speak to one. The
glossary's `listen` is the daemon's, under parents that name which
listener; the tunnel has one.

**Question.** Its names.

**Recommended.** `listen`, kind endpoint, required unless
`listen-socket-file` is set: a loopback IP and a port, refused otherwise
by `shekyl-rpc-transport`'s classifier (`listen.rs`, `classify_listen`). `listen-socket-file`,
kind path, Unix only: a socket in a directory only the tunnel's account
can enter (R0 §1.1's construction), refused on Windows with the typed
code `rpc-socket-dir` has there. The two are unconstructible together.
The tunnel's own name gives `listen` its parent, as `shekyld`'s
`rpc-listen` gives it `rpc`.

### IG-Q111 — the tunnel's table

**Problem.** Rule 83: one table per binary, no environment input.

**Question.** The rest of the tunnel's table.

**Recommended.** `help`, `version`; `network` (one-of, `mainnet`, IG-5);
`config-file` (the account root + `shekyl-rpc-tunnel-<network>.toml`,
IG-13); IG-Q108's five rows; IG-Q109's two switches; IG-Q110's two rows;
`log-file`, `log-level`, `log-category`, `log-size-max` as the daemon's
rows. No pool option: the pool's size is `SESSIONS_PER_CLIENT`, a
constant the daemon enforces (§2, item 4). The tunnel reports on start
the grant it received ("Connected with GRANT; this client is enrolled for
at most CEILING", §4.5) and its fingerprint.

### RT-O37 — the reserved slots

**Problem.** §3.4: the owner's socket and the console can be crowded out
of the one tracker, by anyone who can reach a listener. Rick ruled
reserved slots if so. Two facts shape them.

- **The owner's connections are known at accept**: they arrive on the
  owner's listener, which only the daemon's account can open. A reserve
  the owner's listener alone draws from cannot be taken by anyone else.
- **The console's connections are not.** A channel connection says which
  key it claims only at message 3, and it holds a slot from accept. A
  reserve the channel listener draws from for any connection is a reserve
  anyone can fill with silent connections. Telling the console apart by
  its peer address does not work either: §1's recommended posture
  between machines is an onion service, or a tunnel, whose forward ends
  on the daemon's host, so a remote client, the internet-facing tunnel
  among them, arrives from loopback too.

There is also a conflict with a ruled basis. `SESSIONS_PER_CLIENT`'s
basis (§2, item 4) is "five clients plus the console fit in 25", which
counts the console's four inside `rpc-connections-max` and holds the
console's own fingerprint to the cap. A reserve inside the number
shrinks what is left for everyone else: twenty for five clients, four
for the console and one for the owner leaves nothing for a plaintext
caller or a stranger in its handshake.

**Question.** Where the console's reserved connections arrive, and
whether the reserves count inside `rpc-connections-max`.

**Recommended.**

- **The console reaches a service on a leg only an administrator can
  open**, as the owner reaches a run-as-me daemon on one only it can
  open. The service listens on the channel at a fixed socket in its data
  home (on Windows, a pipe whose descriptor admits the service account and
  Administrators, the data home's own ruled ACL, §7.1). The data home is
  `0700` and owned by the service account, so only that account and an
  administrator can enter it. The handshake and the console key run over
  it unchanged: the leg decides the reserve, the key still decides the
  authority. That listener draws from the console's reserve at accept,
  and a connection on it that does not claim the console key is closed at
  message 3, as any refused claim is. The CLI finds it at the data home's
  fixed path, as it finds the console key (§2, item 2). This replaces the
  service record's TCP address as the console's way in. The record keeps
  serving every other local client.
- **The console keeps the cap**, as the basis states: four.
- **The reserves are outside the operator's number.**
  `rpc-connections-max` bounds what every caller other than the host's
  administrator holds; the owner's leg and the console's leg each have
  `SESSIONS_PER_CLIENT` beyond it, drawn by their own listeners only.
  The process's total is the operator's number plus eight. Under this
  recommendation, the basis reads "five clients fit in 25 with five slots
  to spare, and the console's four are its own".

### Decided here (no question)

- **The typed refusal past the cap** is the bound class
  (`OverResourceBound`), code `bound.sessions`, by IG-Q79's rule that
  each bound has its own dotted code. The daemon answers the session's
  first request with it and closes. A new code is a new variant, so the
  wire's minor version moves (`CORE_RPC_VERSION`). §4.5 gains the row:
  "This client already holds N connections to the node, the most one
  client may hold."
- **The pool lives in `shekyl-rpc-transport`**, beside the initiator, so
  RT-W12's clients can hold one; the tunnel uses it.
- **The extra sessions' idle** is `EXTRA_SESSION_IDLE`, 30 s, beside the
  pool, an Assumption. Its basis: a session costs each side about 2.16 ms
  of CPU to open on the floor device (RT-P6), so an extra session closed
  after 30 s of quiet and opened again costs the daemon at most 2.16 ms
  per 30 s, 0.0072 % of one core, for each extra. RT-P10 measures it.
- **"This computer" resolves to the service first** (§4.5): the CLI
  reads the service's record; with none, it dials the owner's leg. A
  console key that is missing, unreadable or damaged is §4.5's
  console-key failure, and the CLI does not fall back to another leg.
  Both orders are tested.
- **The raw-frame tests keep a seam.** Step 4's tests that write frames a
  well-behaved client never would (an unpadded submission, two
  submissions in one frame, a silent connection, a handshake held at
  message 3) need the stream under hyper. The initiator is two layers: a
  handshake that returns the record stream, and the HTTP session over it.
  The tests take the first layer and write their frames themselves.
- **The kept session** reopens when the daemon closes it, under the
  retry policy (§4.3). A reopen refused at message 3 after a session was
  held is a revocation (§4.5, "The node revoked this client's
  enrolment"); the pool stops, reports it, and does not redial.
- **Submissions** (close-out F2): the tunnel buffers a local request
  whole, reads its JSON-RPC method, and sends a `tx_submit` as one `Full`
  body on a session that carries nothing else until the response, with
  the submission mark armed. The daemon refuses an unpadded submission
  (`submit.unpadded`).

---

## 5. Plan

One pull request. Commits in this order; each builds.

1. This pre-flight, its index rows, and §6.3's sentence.
2. The owner-only file helpers and `sync_dir` move to
   `shekyl-os-account`; `record_path` moves to `shekyl-rpc-rendezvous`.
3. `SESSIONS_PER_CLIENT` in `shekyl-rpc-channel`; the daemon's cap and
   `bound.sessions`; the wire's version.
4. The reserves and, if ruled, the console's leg (after RT-O37 is
   ruled).
5. The initiator in `shekyl-rpc-transport`: the handshake layer, the
   HTTP session, the pool, and a sync target for the CLI. Step 4's tests
   move onto it. The dependency gates of §3.10 run here.
6. The CLI's five words, over `LocalTarget` or the service's record and
   console key (§2, item 2).
7. `shekyl-rpc-tunnel` (after IG-Q108…IG-Q111 are ruled), and the CLI's
   rows from IG-Q108 and IG-Q109.
8. End-to-end tests against a real daemon: enrol, dial, call, revoke,
   and a refused call after revocation; the cap; the reserves; the
   submission's contract. Each names the edit that makes it fail.
9. Documentation: `RPC_CHANNEL.md` (§4.5, §6.3, §8, §13), the grammar's
   rows, the index, the changelog fragment.

---

## 6. Probe registered here

| # | Question | How | Revisits on failure |
|---|---|---|---|
| RT-P10 | Is a pool of `SESSIONS_PER_CLIENT` sessions, with extras closing after `EXTRA_SESSION_IDLE`, the right size under load? | The tunnel on the development workstation against a daemon on the floor device, through a loopback consumer that does not keep HTTP connections alive, at stepped request rates. Measured: requests per second served, the wait for a session at each percentile, handshakes per minute on the daemon, and the daemon's CPU. The registration fixes the rates and the pass lines before the run | `SESSIONS_PER_CLIENT`, `EXTRA_SESSION_IDLE` |
