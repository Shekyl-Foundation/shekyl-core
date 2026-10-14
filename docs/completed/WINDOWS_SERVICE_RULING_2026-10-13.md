# Windows service mode — who answers the SCM (ruled 2026-10-13)

**Status:** CLOSED-as-record (rulings by Rick, 2026-10-13). The rulings are
design of record in [`RPC_CHANNEL.md`](../design/RPC_CHANNEL.md) RT-16,
written fresh from this record on `docs/rt16-windows-service` on
2026-10-14; the patch file named below was never pushed and no longer
exists. The daemon-config items are carried by the daemon-configuration
cutover. Do not implement from this file.

Read at `shekyl-core` `dev` @ `737da312`. Rulings by Rick, 2026-10-13.
Design of record lands in `docs/design/RPC_CHANNEL.md` RT-16 (patch
`0001-docs-rpc-RT-16-shekyld-answers-the-SCM-itself-run-as.patch`, local
branch `docs/rt16-windows-service`, not pushed).

## Rulings

- **Q1 — no separate daemonizer, no wrapper.** `shekyld` itself answers
  the Windows Service Control Manager, in Rust, entered only through
  RT-16's declared service-mode switch. Install/uninstall belong to the
  installer step and `shekyl-cli` (one shared Rust library); `shekyld`
  never registers itself. Restart-on-failure is the SCM's failure actions,
  set at install. POSIX: nothing — systemd/launchd run the foreground
  process. Rejected: a wrapper process (NSSM, WinSW, a Shekyl-built host);
  self-registration.
- **Q2 — the Rust process entry goes to the daemon-config lane.** The SCM
  dispatcher must run at process entry and `main()` is C++
  (`src/daemon/main.cpp:79`); RT-W14 waits for Rust to own the entry.
- **Run-as-me home is always per-user** — `%LOCALAPPDATA%` on Windows,
  never the roaming profile, whatever the token. A machine-wide home exists
  only for the declared service mode and only when the installer created
  it.

Why the question kept recurring: the April daemonizer deletion assumed the
OS manager runs a foreground process on every platform. True for systemd
and launchd; false for the SCM, which kills a registered process that does
not connect to its dispatcher (error 1053). Task Scheduler was the patch
for that gap; it is rejected (RT-16, §12).

## For the daemon-config lane (Round 0 inventory)

1. **Own the process entry.** The SCM dispatch sits at entry, behind the
   service-mode switch; the switch is a daemon-config option (no new C++
   options). Outside the SCM the dispatcher connect fails → rule-82 refusal;
   SCM start without the switch fails. Service reports running when the
   machine-wide rendezvous is published (RT-15/§7.1 readiness event).
2. **Delete the elevation branch** in
   `src/common/daemon_default_data_dir.cpp` (elevated → `%ProgramData%`,
   else roaming `%APPDATA%`). It infers mode from the account, which RT-16
   forbids. Threat, assessed: an unprivileged local user on a shared Windows
   host can pre-create `%ProgramData%\shekyl\shekyl.conf`; `main.cpp:176-210`
   loads `<default data dir>/shekyl.conf` unasked, so any elevated `shekyld`
   takes the attacker's proxy (exposes the node's traffic origin) or log
   path (admin file write). Narrow, but the fix is a deletion. The file's
   "silent relocation" warning is obsolete — every release wipes.
3. **Windows default config location** must never be a path an
   unprivileged user can pre-create (ties to the R2 default-path load).
4. **`removed_flags.cpp:158-162`** still sends Windows operators to Task
   Scheduler; rewrite when the table moves to Rust (also an RPC_CHANNEL
   §11.2 row owned by RT-W14).

## Noted for the Rust `main()` work (hand over when that lane opens)

- **Run-as-me does not stop cleanly.** `src/common/util.h:193-201`: every
  console event other than Ctrl-C/Ctrl-Break (window close, logoff,
  shutdown) logs "Exiting without saving" and returns FALSE, so the process
  is terminated, not stopped. RT-16's "stops at logout" is not yet true.
  Severity low (stores are transactional; Tor exits via `TAKEOWNERSHIP`).
  Fix during the Rust rewrite: console events and the SCM's stop /
  pre-shutdown controls feed one stop path.
