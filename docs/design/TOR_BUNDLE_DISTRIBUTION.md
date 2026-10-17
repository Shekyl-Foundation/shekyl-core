# Tor bundle distribution — Tor by default, declined only explicitly, and shipped in every artifact

**Status: RULED 2026-10-06 — ratified as a whole by Rick; §5 step 1 (Linux)
and step 2's Windows half are implemented; step 2's macOS half and steps 3
and 4 are not.** He ratified the rows as they stood at
`4ad467800`, with two amendments that are folded in below: TB-7's third part
became the exact-contents rule, and the system-supplied libraries are recorded
(§5a). What step 1 landed is listed in §5; until step 4 a node with no usable
tor still starts, as PWD-E7 ruled, and now says so at warning level.
Identifier family `TB-1…TB-n` (index row registered at birth per rule 94
§1). Decision authority: Rick. Rule 26 is cited: this changes a security
boundary (what the Tor pin proves) and a startup contract.

This round amends two ruled documents and restates neither:
[`P2P_2_ENDPOINT_ROUND.md`](P2P_2_ENDPOINT_ROUND.md) PWD-E7 (the daemon's
overlay posture) and
[`ARCHIVAL_BOND_2D2_SP_T0_TOR.md`](ARCHIVAL_BOND_2D2_SP_T0_TOR.md) DQ-T0.5 (the
pin and its packaging). Code anchors below were verified at `dev` `e0fb3eaa8`.

---

## 1. Why this round exists

Tor has become essential to a Shekyl node (Rick, 2026-10-06), and the tree does
not say so. "Essential" is ruled in TB-1 as: a node has Tor unless its operator
has explicitly declined it. PWD-E7 was ruled when Tor was an overlay posture: its seam table
reads "tor control unavailable ⇒ no overlay inbound; the node is outbound-only
on that zone", and the code does exactly that. Installing `v3.1.0-alpha.9` on
the Foundation's hosts showed what that costs once Tor is not optional.

## 2. What was found (each item observed, not inferred)

1. **No published artifact carries tor.** The release job copies four binaries
   into the package (`.github/workflows/gitian.yml:132`) and never mentions tor.
2. **A node with no pinned tor runs clearnet-only and says so at a level nobody
   reads.** The message is `MINFO` (`src/p2p/net_node.inl:869`), hidden at the
   default log level. That is PWD-E7's ruled "calm skip"
   (`rust/shekyl-tor-control-daemon/src/blocking.rs:65`), not a defect in the
   code.
3. **A staged bundle under a name the resolver does not compose is not found.**
   Internal hosts held the pinned binary — its digest equals the x86_64 pin —
   under `/opt/shekyl/tor-expert-bundle-<version>/tor/`, while the resolver
   composes `/opt/shekyl/<bundle_version>-<bundle_target>/tor`
   (`rust/shekyl-tor-control-client/src/binary.rs:361`). Those daemons ran
   without managed Tor.
4. **The launcher passes its whole environment to tor.** The spawn builds a
   command from the verified path and sets no environment
   (`rust/shekyl-tor-control-client/src/control/actor.rs:890`); no file in the
   three Tor crates clears the environment or sets a variable in it. `LD_PRELOAD`, `LD_LIBRARY_PATH` or
   `DYLD_INSERT_LIBRARIES` from a shell, a unit file or a profile therefore
   loads code into the process whose file was hash-verified.
5. **The Linux `tor` in the Expert Bundle does not use the libraries shipped
   beside it unless told to.** It needs `libevent-2.1.so.7`, `libssl.so.3` and
   `libcrypto.so.3` and carries no `RPATH` or `RUNPATH`. Run with the three
   bundled copies beside it and no `LD_LIBRARY_PATH`, the loader took all three
   from the system directory; with `LD_LIBRARY_PATH` set to the bundle's `tor/`
   directory it took the bundle's. What that meant on the hosts probed on
   2026-10-06, as they were that day and not as a property of any
   distribution: the internal Ubuntu 24.04 hosts would have run tor on their
   own OpenSSL (3.0.13 there) in place of the bundle's (3.5.8), and the floor
   device's image (Ubuntu 26.04) had no `libevent-2.1.so.7`, so tor would not
   have started on it. The pin covers the `tor` file only.
6. **The macOS `tor` names its one library by `@executable_path`**
   (`libevent-2.1.7.dylib`, read from the binary's strings; not run). The
   Windows bundle ships `tor.exe` with no library beside it.
7. **The pin is behind, and three published targets have none.** See §4.
8. **This build of tor is GPL.** `tor --version` prints that it is covered by
   the GNU General Public License.
9. **FreeBSD has no Expert Bundle.** The Tor Project publishes Windows, macOS
   and Linux; Shekyl publishes a FreeBSD build.
10. **Pointing the Linux loader at a directory makes every library in that
    directory a candidate, not just the three the bundle ships.** `tor` also
    needs `libz.so.1`, which the bundle does not carry. With a `libz.so.1`
    placed in the bundle directory and `LD_LIBRARY_PATH` set to it under a
    cleared environment, the loader took that copy. So the fix for finding 5
    opens this, and a pin over four named files does not close it.
11. **Windows searches the executable's own directory before the system's.**
    `tor.exe` imports only operating-system libraries (`ADVAPI32`, `CRYPT32`,
    `IPHLPAPI`, `KERNEL32`, `SHELL32`, `SHLWAPI`, `USER32`, `WS2_32` and the
    universal C runtime's `api-ms-win-crt-*`), read from its import table. That
    does not help: a library of one of those names placed beside `tor.exe` is
    found first unless Windows treats it as a known system library, and the
    portable zip unpacks into a directory the user can write. This is search
    order, not an environment variable. Windows also treats `VERSION.DLL` and
    `version.dll` as one name, so any rule that matches on a file's name has to
    do the same.
12. **glibc searches subdirectories of a library-path entry before the entry
    itself.** With `libz.so.1` placed only in
    `<tor dir>/glibc-hwcaps/x86-64-v2/` and the loader pointed at the tor
    directory under a cleared environment, that copy was loaded (glibc 2.41).
    A listing of the tor directory's top level shows a `glibc-hwcaps` entry
    and no library. A rule that looks for library files at the top level
    passes this.
13. **OpenSSL inside the managed tor reads a configuration file from a path
    any local account can create.** Every Expert Bundle checked (2026-10-16:
    `linux-x86_64`, both macOS targets and `windows-x86_64` at 15.0.24 and
    15.0.25, and `linux-aarch64` 16.0a13) compiles in `OPENSSLDIR`
    `/var/tmp/dist/openssl/ssl`, with its modules and engines directories
    beside it. On Unix `/var/tmp` is world-writable and `dist` does not
    exist; on Windows the same string is a drive-relative path, under the
    current drive's root, and `OSSL_WINCTX` is undefined, so no registry
    setting replaces it. Tor initialises OpenSSL without
    `OPENSSL_INIT_NO_LOAD_CONFIG` (`crypto_openssl_mgt.c`, identical at
    `tor-0.4.9.13` and `tor-0.4.9.14`), so OpenSSL reads `openssl.cnf` there
    whenever `OPENSSL_CONF` is unset. A configuration can name a provider or
    engine module by absolute path, and OpenSSL loads it into tor. Given a
    configuration that names a missing provider module, with diagnostics on,
    tor aborts at start (`subsysmgr.c:147`) on every target run, while a
    merely malformed file is ignored: Linux x86 (15.0.24), Linux aarch64 on
    the floor device (16.0a13), macOS aarch64 (15.0.24 and 15.0.25) and
    Windows (both builds, `0xC0000409`). macOS x86_64 was not run. The macOS
    arms ran on an ad-hoc-signed copy of the pinned files: as shipped, the
    aarch64 `tor` and its `libevent` carry no code signature, and Apple
    Silicon kills them at exec (TB-11's launch test). On Windows `C:\`
    lets any authenticated user create a directory, and a new `C:\var`
    inherits Modify for all of them, so any local user can write
    `C:\var\tmp\dist\openssl\ssl\openssl.cnf`; with `OPENSSL_CONF` unset, a
    file placed at that default in a sandbox did not load, for a reason not
    yet traced, so the default stays a live risk. Nothing was planted at a
    real path. TB-7 part 2 closes it by naming the launcher's blank file in
    `OPENSSL_CONF`. The bundles also compile in `MODULESDIR` and `ENGINESDIR`
    under the same root; the launch reaches neither (no configuration names
    a module, no provider is loaded by name, `HardwareAccel` is off).
    **Reopen** when a typed option adds hardware acceleration or a named
    provider: the launch then names an absolute directory it owns
    (`AccelDir`, `OPENSSL_MODULES`).

## 3. The rulings

Every row was ratified by Rick on 2026-10-06. The last column records anything
said about a row on its own.

| Row | Proposal | Ruled |
| --- | --- | --- |
| **TB-1** | **A node has Tor unless its operator explicitly declines it.** The default ephemeral posture is not an optional overlay that is quietly absent: it is present, or it was declined on the command line. Clearnet-only is a **supported, explicit operator choice**, made with `--no-ephemeral-tor`, and a node running that way says so at warning level on every boot. Who it is for: an operator who wants to take part and is not relying on network-level privacy for the node (an exchange, the Foundation's own infrastructure); a node whose Tor is failing; a place where Tor is watched or blocked. What it costs, stated: that node's address is visible to its peers, as on any clearnet node, and its own transactions get Dandelion++ over clearnet and no onion route. The clearnet link is encrypted only where the Noise layer is on, which is an option today (`--clearnet-transport-encrypt`, off by default) and the default once the flip lands; until then a declined Tor means a plaintext link. It is a choice about one node's transport; no wallet guarantee and no consensus rule depends on it. This replaces PWD-E7's seam row "tor control unavailable" with TB-2 and TB-3; the rest of PWD-E7 (two postures, no verifier, no persisted key, the forbidden direction) stands unchanged | **Rick, 2026-10-06**: reading (a) of two put to him — clearnet-only is supported and explicit. On the plaintext cost: "the cost it describes ends at the Noise flip, which will occur shortly now that we have alpha.9 in testnet" |
| **TB-2** | **A startup configuration defect refuses the start.** On a `Pinned` target, no usable tor at startup (not found, a digest mismatch on any pinned file, anything in tor's directory that is not pinned (TB-7), not a file, not executable, unreadable) stops the daemon before any socket opens, with the remedies named. It is deterministic and the operator can fix it. `--no-ephemeral-tor` alone is the way past it: the flag is TB-1's explicit decline, and needs no operator-provisioned Tor beside it | Rick, 2026-10-06 |
| **TB-3** | **A runtime failure is the supervisor's** ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md)). A verified tor whose bootstrap fails, or that dies, is retried with capped backoff and never given up; a Tor-only node waits and announces, and a dual-posture node runs clearnet meanwhile. One mechanism, one job: TB-2 is about what is installed, TB-3 about what the network did | Rick, 2026-10-06; amended by `TSR` at its ratification, 2026-10-15 |
| **TB-4** | **A target's Tor disposition is a type with no third state.** `Pinned(pin)` or `Unavailable { reason }`; a build target with neither does not compile. Today `CURRENT_PIN: Option<TorPin> = None` cannot tell "not pinned yet" from "ruled unavailable". TB-2 applies to `Pinned` targets only. An `Unavailable` target starts, warns that managed Tor does not exist on this platform, and names the remedy | Rick, 2026-10-06 |
| **TB-5** | **FreeBSD is `Unavailable`: the operator installs tor and attaches it.** `pkg install tor`, then `--tx-proxy` for outbound and an operator-provisioned onion service with `--anonymous-inbound` for inbound (PWD-E7's second posture, with its durable-address warning). Shekyl ships a user guide for it. Carrying a tor in the FreeBSD artifact is a later look, not this round | **Rick, 2026-10-06**: "users there will have to install their own"; a guide at least, incorporation into our package to be looked at |
| **TB-6** | **Every artifact that carries `shekyld` carries the pinned bundle, and the bundle's tarball is checked before it is opened.** The property: the Expert Bundle tarball enters the build as a pinned input, its digest is compared with TB-9's file before anything is extracted from it, and a difference fails the build, whatever does the fetching. It is not a download in the packaging step, so the archives, the zip and the installer carry it as well as the `.deb` and `.rpm`, and the build is offline and reproducible from that point. The mechanism is the implementing change's to choose: a gitian `files:` entry records an input's hash and does not refuse a wrong one, whereas the depends system both fetches and checks (`$(package)_sha256_hash`). Placement: a directory of its own beside the executable in archives (TB-7 is why it cannot share one), under `/opt/shekyl/<bundle_version>-<bundle_target>/` in system packages, never in `/usr/local/bin`, where it would shadow a distribution's tor. Only `tor` and the libraries it loads are shipped — the pluggable transports are 30 MiB Shekyl does not use | Rick, 2026-10-06 |
| **TB-7** | **The pin covers every file in tor's directory, the directory holds nothing else, and the launcher lets nothing else in.** Three parts. (1) Each pinned file has its own digest through the same canonicalize-then-hash gate: on Linux `tor`, `libevent-2.1.so.7`, `libssl.so.3`, `libcrypto.so.3`; on macOS `tor` and `libevent-2.1.7.dylib`; on Windows `tor.exe`. (2) The launcher clears the environment and then sets a closed set, each value from a trusted source and none from the parent's environment: `OPENSSL_CONF` on every platform, to the launcher's blank file in the data directory; on Linux the library path, to the verified binary's own directory; on Windows `SystemRoot`, from the OS (`GetSystemWindowsDirectoryW`). Every Expert Bundle's OpenSSL compiles in `OPENSSLDIR` `/var/tmp/dist/openssl/ssl` and tor does not opt out of OpenSSL's configuration loading, so without `OPENSSL_CONF` a file any local account can create there could make OpenSSL load a module into tor (§2 finding 13). (3) **The tor directory contains exactly the pinned files and nothing else**: no other entry, no subdirectory, names compared without regard to case on Windows. It is an allowlist, not a scan for library-looking names, because the loader does not confine itself to names a scan would think of or to the top level — §2 findings 10 to 12. It is also why the bundle needs a directory of its own. Three negative tests, each of which must refuse: a planted file at the top level, a planted `glibc-hwcaps/<level>/libz.so.1`, and a planted `VERSION.DLL` | Rick, 2026-10-06 (part 3 in this form is his amendment at ratification; part 2's Windows variable, 2026-10-15, from the TSR-Q7 Windows run, landed in #1083; part 2 amended 2026-10-16 from "at most one variable" to the closed set, adding `OPENSSL_CONF`) |
| **TB-8** | **The `PATH` tier is deleted for a `Pinned` target.** A `tor` found on `PATH` has its libraries elsewhere and cannot pass a four-file pin, and `PATH` is the widest check-to-exec window the resolver has. The override, beside-the-executable and `/opt/shekyl` tiers remain | Rick, 2026-10-06 |
| **TB-9** | **The pins are one data file.** `build.rs` reads it and emits constants: the pin stays compiled in and is never read at runtime. The file is the only source for what the packaging side needs — tarball digest, per-file digests, bundle and tor versions, target label, the `Unavailable` dispositions — and the build recipe and the packaging check read it, they do not copy it. Two gates: the packaging job hashes the files it is about to pack against the file and fails on a difference (a test edits a digest and sees the build fail), and the file's set of targets equals the set of compiled arms | Rick, 2026-10-06 |
| **TB-10** | **Re-pin to the current stable Expert Bundle**, 15.0.25 (tor 0.4.9.14), with the digests in §4. `linux-aarch64` stays on the alpha line, at 16.0a13 (tor 0.4.9.13), under DQ-T0.5's existing ruling and reopen criterion | Rick, 2026-10-06; re-pinned from 15.0.24 to 15.0.25 on the stable targets, Rick, 2026-10-16 |
| **TB-11** | **Windows and macOS become `Pinned` only with a launch test each.** Their digests are verified (§4); what is missing is evidence that the pinned binary starts under Shekyl's launcher on those platforms. The Windows test also asserts that `tor.exe`'s import table names only operating-system libraries, so that a future bundle which starts shipping its own DLL is noticed. The macOS test establishes what the signature on the pinned binary is and whether it carries the hardened runtime; inside a macOS `.app` the tor binary falls under Shekyl's code signing and notarization | Rick, 2026-10-06. **Windows half satisfied 2026-10-17**: the `tor-pin-verify` Windows entry, RUN_URL |
| **TB-12** | **TB-2 lands last, and "every published target" includes the GUI wallet's installers.** The refusal is merged only after every published target is `Pinned` with its bundle shipped, or `Unavailable`. That set is `shekyl-core`'s own artifacts **and** `shekyl-gui-wallet`'s (`.deb`, AppImage, Windows setup, macOS `.dmg`), which carry `shekyld` as a sidecar built from the core tag and therefore inherit its pin and need the bundle beside it. That work is in another repository and is tracked there; without it the refusal stops the GUI's daemon on every platform, and nothing in this repository would show it | Rick, 2026-10-06 |
| **TB-13** | **Licences travel with the binary.** Every artifact that carries tor carries the bundle's licence texts and the location and signature of the source of the tor version its pin names. Whether a pointer to the signed upstream source meets the GPL's source obligation is to be confirmed before beta, not assumed | Rick, 2026-10-06 |

### Refused in this round

| Name | Status | Why, and what reopens it |
| --- | --- | --- |
| `--tor-pin-override <sha256>` | **REJECTED** | It is flexibility provisioned ahead of need, and it turns a structural gate into one a unit-file edit opens. **Reopen** if a Tor security advisory cannot be answered by a Shekyl release in time |
| A signed pin manifest that moves between releases | **REJECTED** | It is an update channel: one key becomes "run this binary on every node", and a startup fetch is a beacon. A Tor CVE costs a patch release, as a CVE in any shipped dependency does. **Reopen** on the same criterion as above |
| Depending on a distribution's `tor` | **REJECTED** | A distribution build cannot match the pin; "our tor, their OpenSSL" is the same objection one layer down (finding 5) |
| Building tor from the signed source inside gitian | not this round | The route to a pinned FreeBSD and a stable `linux-aarch64`. A round of its own; `docs/FOLLOWUPS.md` carries its reopen trigger for `linux-aarch64` |

## 4. The pins TB-10 and TB-11 adopt

Every tarball carries a valid signature (`VALIDSIG`, not only `GOODSIG`) from
the Tor Browser Developers key `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`
(signing subkey `022DA248432D2A0E0F54E65E316C1FACD62D07D9`), the key
`binary.rs`'s `TOR_SIGNING_KEY_FPR` names. The stable bundles were downloaded
from the Tor Project's archive on 2026-10-17 and ship tor `0.4.9.14`; the
`linux-aarch64` alpha was downloaded on 2026-10-06 and ships tor `0.4.9.13`.

| Target | Bundle | Tarball SHA-256 |
| --- | --- | --- |
| `linux-x86_64` | 15.0.25 (stable) | `19cf18726eecb362e0f21d27afa9ea9efe5da928bfdfbb1ceb5fe54519e87f4a` |
| `linux-aarch64` | 16.0a13 (alpha) | `e1685ff7a531e7b50b77ce231e8be397c835dd2dcb96b2fd8feb02c638acc517` |
| `windows-x86_64` | 15.0.25 (stable) | `c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252` |
| `macos-aarch64` | 15.0.25 (stable) | `a3febb6179152b0b4f56a0f5cc57bf5cc8ecef7db35e7c3e9d5a044c8158c26c` |
| `macos-x86_64` | 15.0.25 (stable) | `e1ae4d4a734d28bb590839188511deb3cebc26fcbce9df66d01b2c452060fe95` |

Extracted files, by target:

| Target | File | SHA-256 |
| --- | --- | --- |
| `linux-x86_64` | `tor` | `39c9db0654d2ec218892bd00f75eccb5b641a7222754436c2e4a8d2f764a57d3` |
| | `libevent-2.1.so.7` | `b51ca562ec232785856c454ce4f3621d957f39d0db87919e237590b0331544ff` |
| | `libssl.so.3` | `9c2438d086d6c299db04b0bc337bbc8c0acd26c19c71eada2173a5b2ef7cecac` |
| | `libcrypto.so.3` | `418208c5c738864cb5653f3eeab650debcc71afbe50d08b0bd5a04b20f1d3c05` |
| `linux-aarch64` | `tor` | `5ad180229237d10e670ae0475b21d788272da0c13bb89c2617223afcfe3ff477` |
| | `libevent-2.1.so.7` | `097958f586ffce01273a57557e17062357d92343724e1f112ea61ad8261ce577` |
| | `libssl.so.3` | `080e70629ffe87e3c5bbbb59bc231da4c5d68100dd6b43b522bcaf8447d85eaf` |
| | `libcrypto.so.3` | `f50977cdfd82a28ab7ac327daa11841486193888365a149f1409ce5a3b1e61b3` |
| `windows-x86_64` | `tor.exe` | `8c38513b3c4584154158e7c584f4144849dc679a64cd679553d72dad28230c54` |
| `macos-aarch64` | `tor` | `7d5a89b6cec99aab47420040ad86dd5fd5174192e71b6c201b0b10170ba57ebb` |
| | `libevent-2.1.7.dylib` | `6dde3faf59255b7cf0cc20d0b3cdf78622266fbf13c534300b8884c76d89b739` |
| `macos-x86_64` | `tor` | `e249a521aa5b0ff44a39c1dc4b5707ae8cb109d8a26c637b6acbbf6832bf2f14` |
| | `libevent-2.1.7.dylib` | `38aea0316e01e1fc52a15941bf523c8bc018ca90655cfa90de568b4a86a82b4b` |

The Windows bundle's `tor/` also holds `tor-gencert.exe`, a directory
authority's tool that Shekyl does not ship. `tor.exe` links OpenSSL, libevent
and zlib statically, so its licence texts include `docs/zlib.txt`. Its import
table names 21 DLLs and its delay-load table names none: `ADVAPI32.dll`,
`CRYPT32.dll`, `IPHLPAPI.DLL`, `KERNEL32.dll`, `SHELL32.dll`, `SHLWAPI.dll`,
`USER32.dll`, `WS2_32.dll` and thirteen universal C runtime API sets
(`api-ms-win-crt-{conio,convert,environment,filesystem,heap,locale,math,private,runtime,stdio,string,time,utility}-l1-1-0.dll`).
That list is the Windows row's `imports`; it is the same set the 15.0.24
`tor.exe` imports.

The Linux and Windows rows are the pin of record: they are the `linux` and
`windows` rows of `config/tor_pins.json`, which `build.rs` compiles and the
packaging tool reads, recorded through `RELEASE_CHECKLIST.md`'s "Bundled Tor
pin current" procedure. The macOS rows remain the ruling's evidence until
TB-11 adopts them; those targets are `unavailable` in the pin file meanwhile,
with that as the stated reason.

## 5. Order of work

1. **Linux, both architectures, every artifact type:** TB-6 to TB-10 and TB-13,
   with TB-4's type and TB-1's every-boot warning for a declined Tor. Validated by the crate's tests, the `tor-pin-verify`
   workflow at the new bundle version, and a gitian dry run. **LANDED.** Where
   each row lives:
   - TB-4, TB-9: `config/tor_pins.json` is the one data file.
     `rust/shekyl-tor-control-client/build.rs` compiles the build target's row
     into `binary::CURRENT_DISPOSITION` (`TorDisposition::Pinned` or
     `Unavailable`) and fails the build for a target with no row.
     `scripts/ci/check_tor_pin_targets.py` holds the file's hosts equal to the
     gitian descriptors' hosts. "The set of compiled arms" is read as that:
     with the row compiled by `build.rs` there are no hand-written `cfg` arms
     left to compare, so the gate compares against what the release builds.
   - TB-6: `scripts/release/tor_bundle.py` checks the tarball's digest before
     opening it and stages only the pinned files. The Linux gitian descriptor
     stages into `tor/` beside the binaries, with `tor-licenses/` beside that;
     the package job installs the same files under
     `/opt/shekyl/<bundle_version>-<bundle_target>/`. The descriptor stages
     with `--no-fetch`: the tarball comes from the sources cache that
     `gitian-build.py` filled before the build, and a cache miss stops the
     build instead of downloading inside it.
   - TB-7: `binary::verify_candidate` (exact contents, per-file digests, one
     canonical directory carried by the witness) and
     `control::launch::managed_tor_command` (cleared environment, then the
     closed set of `control::launch::LaunchEnvironment`: `OPENSSL_CONF` naming
     the launcher's blank file everywhere, the loader path from the witness
     on Linux, `SystemRoot` on Windows). The cleared environment applies on
     every platform. `openssl_reads_only_the_launchers_configuration` proves
     the pinned tor's OpenSSL reads the file `OPENSSL_CONF` names, and that
     the launch starts with the blank file there. A Windows `tor.exe` does not start without `SystemRoot`: the
     0.4.9.13 build aborts within about 0.1 s with `0xC0000409`, "subsystem
     crypto (at 7) initialization failed", and restoring that one variable
     is enough (observed on Windows, 2026-10-15; the launcher change is
     #1083). The launcher sets it
     from `GetSystemWindowsDirectoryW`, never from the parent's environment.
     A failed call is `ControlError::SystemDirectory` and carries the OS
     code, not a path. `the_managed_launch_environment_is_exact` lists the
     variables the command sets; it cannot see `env_clear`. The proof is
     `managed_tor_child_inherits_no_environment`, which re-executes with a
     poisoned `SystemRoot` on Windows and reads the environment the child
     received. The Windows job in `build.yml` runs both, and clippy for
     this crate.
     The launcher also names every file tor would otherwise find by itself:
     `--torrc-file`, `--defaults-torrc`, `--GeoIPFile` and `--GeoIPv6File`
     all name one zero-length file, `blank`, which it writes in the
     `DataDirectory`. The directory is owner-only, and the write does not
     follow a symlink or a hard link. Without them tor reads its compiled-in
     defaults, and the pinned Linux bundle's are under `/var/tmp/dist/tor/`
     (`etc/tor/torrc`, `etc/tor/torrc-defaults`,
     `share/tor/geoip`, `share/tor/geoip6`), a path any local account can
     create; command-line options override only the keys they name. On
     Windows the torrc is under the user's `APPDATA`, found through the shell
     API, which the cleared environment does not move. The live test is
     `managed_tor_reads_no_configuration_but_its_own`: tor's own log must name
     no configuration or GeoIP file but that one.
     Where the launcher sets the loader path, a directory whose own path
     holds `:`, `;` or `$` is refused: the loader reads that variable as a
     list and would search other directories than the one checked.
   - TB-8: `binary::candidate_from` takes no `PATH`.
   - TB-10: the two Linux rows of §4.
   - TB-13: `tor-licenses/` in each archive and `/usr/share/doc/shekyl/tor/`
     in each package: the bundle's licence texts and a `SOURCE.txt` naming
     the bundle, its digest and signing key, and the `tor` source and its
     signature.
   - TB-1: `--no-ephemeral-tor` with no operator-provisioned Tor logs the
     clearnet-only warning on every boot. A node with no tor found, which has
     not declined, also warns (it was an info line); that state becomes a
     refusal in step 4.
   - macOS, FreeBSD, riscv64 Linux and Android are `Unavailable` rows with
     their reasons. FreeBSD, riscv64 Linux and Android are rulings. The macOS
     rows are not: they also carry `"pending": "TB-11"`,
     which says the target is unavailable only until its pin is adopted. A
     pending row compiles as `Unavailable`, which is what the binary does
     today, so TB-4's two states stand at runtime; the marker is for the gate.
     `check_tor_pin_targets.py` prints every pending row and fails on any
     with `--refuse-pending`.
2. **Windows and macOS:** TB-11, a pin and a launch test for each; and the
   GUI wallet's installers (TB-12), in `shekyl-gui-wallet`. **The Windows
   half is LANDED**; macOS and the GUI wallet's installers are not:
   - The pin: the `windows` row of `config/tor_pins.json`, `tor.exe` only,
     with `imports`, the DLLs it may import (§4). `build.rs` and
     `tor_bundle.py`'s `load_pins` both refuse a Windows row without the list
     and any other row with one.
   - The import check: `tor_bundle.py` reads `tor.exe`'s PE import table when
     it stages and when it verifies, and refuses a DLL the list does not name
     and any delay-load import. A future bundle that starts shipping or
     loading its own DLL is refused at packaging, not noticed in the field.
   - The package: the Windows gitian descriptor stages the bundle into `tor/`
     beside the binaries, with `tor-licenses/`, and verifies it, as the Linux
     one does.
   - The launch test: `tor-pin-verify`'s `windows-x86_64` entry fetches the
     bundle, checks its signature, stages it, and runs the launcher crate's,
     the daemon facade's and the wallet's live tests against it (RUN_URL).
   - A Windows daemon with no bundle beside it warns and starts, as every
     pinned target does until step 4.
3. **FreeBSD:** TB-5's `Unavailable` arm and its user guide.
4. **The refusal:** TB-2, under TB-12. Its change turns on
   `--refuse-pending` where `grep-gates` runs `check_tor_pin_targets.py`, so
   it cannot merge while a published target is still waiting for its pin.
   Without that, "every target is `Pinned` or `Unavailable`" is already true
   of the Windows and macOS rows and TB-12 would guard nothing.

The Foundation's own hosts are reconfigured one at a time after step 1, to the
canonical location, watching the network recover from each dropped node.

## 5a. What stays system-supplied, on purpose

The pin cannot cover a file Shekyl has no source for. With the loader pointed
at the bundle, the Linux `tor` still takes these from the system (observed on
`linux-x86_64`; the `linux-aarch64` `tor` names the same set — `readelf -d`
lists `libz.so.1` as `NEEDED` in both, so neither links zlib statically. The
16.0a13 bundle carries a `docs/zlib.txt` that the 15.0.25 bundle does not;
that is a licence text for a library the bundle does not ship, and Shekyl
does not stage it):

- the glibc family — the dynamic loader, `libc`, `libm`, `libdl`,
  `libpthread` — and `libgcc_s`;
- **`libz.so.1`.**

zlib decompresses data that arrives from the network, so this is "our tor,
their zlib": the objection finding 5 raises about OpenSSL, at a smaller size.
It is accepted because the Expert Bundle ships no zlib and Shekyl does not build
tor; a planted copy is refused by TB-7 part 3, but the system's own copy is
whatever the distribution maintains. **Reopen** with the round that builds tor
from the signed source, which is the only place a pinned zlib can come from.

A missing system library fails a launch the same way the missing `libevent`
would have (finding 5). The floor device's image carries `libz.so.1` (probed
2026-10-06); the launch run on it confirms the whole set rather than taking
that probe as the answer.

### Outside the threat model, stated once

- **`/etc/ld.so.preload` on Linux.** It is root's file. An attacker who can
  write it can replace `shekyld`; the pin was never a defence against root.
- **macOS `DYLD_*` variables.** TB-7 part 2 clears them from the child's
  environment, and the library is named by `@executable_path`, which no search
  path overrides. No reliance is placed on a hardened-runtime signature: a
  scan of both macOS binaries from Linux found no code signature in them, the
  Tor Project signs the tarball and not necessarily the binary inside, and if
  the hardened runtime ever protects this process it will be through Shekyl's
  own signature once tor sits inside the `.app` (TB-11).
- **A local attacker who can write tor's directory between the check and the
  exec.** DQ-T0.5 already names this window and its reopen criterion (verify
  and exec the same descriptor). TB-7 widens what is checked, not the window.

## 6. What breaks first if this is wrong

- **TB-7's environment clearing** removes variables tor itself may read. The
  managed launch passes everything as arguments (data directory, control
  port, SOCKS port, log, configuration files). The one dependence found so
  far is Windows `SystemRoot`, which the launcher sets from the OS; the
  crate's live lifecycle tests on each platform are where another would
  show.
- **The empty GeoIP table** maps no address to a country. Nothing the
  launch configures asks for one; a future typed knob that selects or
  excludes nodes by country (`{cc}` in `ExcludeNodes`) would silently match
  nothing, and needs a real GeoIP file pinned beside tor.
- **TB-2** turns an install mistake into a daemon that does not start. That is
  the intent, and TB-12 is what keeps it from reaching a platform that cannot
  satisfy it.
- **TB-8** removes a path a developer may be using. A developer's own tor is
  the override tier's job, and it stays — gated like every tier, so on a pinned
  target it must name the `tor` in a directory holding exactly the pinned
  files. Pointing it at a full extracted Expert Bundle is refused
  (`pluggable_transports/` is not pinned); `COMPILING_DEBUGGING_TESTING.md`
  says how to stage one.
