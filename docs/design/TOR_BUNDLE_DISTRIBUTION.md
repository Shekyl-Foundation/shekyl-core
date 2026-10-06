# Tor bundle distribution — Tor is mandatory, and every artifact ships it

**Status: OPEN — PROPOSED 2026-10-06, awaiting ruling.** Nothing here is ruled
except where a row says who ruled it and when. No code follows from an unsigned
row. Identifier family `TB-1…TB-n` (index row registered at birth per rule 94
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
not say so. PWD-E7 was ruled when Tor was an overlay posture: its seam table
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
   three Tor crates clears or sets one. `LD_PRELOAD`, `LD_LIBRARY_PATH` or
   `DYLD_INSERT_LIBRARIES` from a shell, a unit file or a profile therefore
   loads code into the process whose file was hash-verified.
5. **The Linux `tor` in the Expert Bundle does not use the libraries shipped
   beside it unless told to.** It needs `libevent-2.1.so.7`, `libssl.so.3` and
   `libcrypto.so.3` and carries no `RPATH` or `RUNPATH`. Run with the three
   bundled copies beside it and no `LD_LIBRARY_PATH`, the loader took all three
   from the system directory; with `LD_LIBRARY_PATH` set to the bundle's `tor/`
   directory it took the bundle's. On an Ubuntu 24.04 host that means the
   distribution's OpenSSL 3.0.13 in place of the bundle's 3.5.8; on the floor
   device (Ubuntu 26.04) `libevent-2.1.so.7` is absent and tor would not start.
   The pin covers the `tor` file only.
6. **The macOS `tor` names its one library by `@executable_path`**
   (`libevent-2.1.7.dylib`, read from the binary's strings; not run). The
   Windows bundle ships `tor.exe` with no library beside it.
7. **The pin is behind, and three published targets have none.** See §4.
8. **This build of tor is GPL.** `tor --version` prints that it is covered by
   the GNU General Public License.
9. **FreeBSD has no Expert Bundle.** The Tor Project publishes Windows, macOS
   and Linux; Shekyl publishes a FreeBSD build.

## 3. Proposed rulings

Each row is PROPOSED unless its last column says otherwise.

| Row | Proposal | Ruled |
| --- | --- | --- |
| **TB-1** | **Tor is mandatory.** The default ephemeral posture is not an optional overlay. This replaces PWD-E7's seam row "tor control unavailable" with TB-2 and TB-3; the rest of PWD-E7 (two postures, no verifier, no persisted key, the forbidden direction) stands unchanged | — |
| **TB-2** | **A startup configuration defect refuses the start.** On a target with a pin, no usable tor at startup (not found, digest mismatch, not a file, not executable, unreadable) stops the daemon before any socket opens, with the remedies named, unless `--no-ephemeral-tor` is given. It is deterministic and the operator can fix it | — |
| **TB-3** | **A runtime failure degrades, as PWD-E7 ruled.** A verified tor whose bootstrap then fails leaves the node outbound-only on that zone and logs at error. One mechanism, one job: TB-2 is about what is installed, TB-3 about what the network did | — |
| **TB-4** | **A target's Tor disposition is a type with no third state.** `Pinned(pin)` or `Unavailable { reason }`; a build target with neither does not compile. Today `CURRENT_PIN: Option<TorPin> = None` cannot tell "not pinned yet" from "ruled unavailable". TB-2 applies to `Pinned` targets only. An `Unavailable` target starts, warns that managed Tor does not exist on this platform, and names the remedy | — |
| **TB-5** | **FreeBSD is `Unavailable`: the operator installs tor and attaches it.** `pkg install tor`, then `--tx-proxy` for outbound and an operator-provisioned onion service with `--anonymous-inbound` for inbound (PWD-E7's second posture, with its durable-address warning). Shekyl ships a user guide for it. Carrying a tor in the FreeBSD artifact is a later look, not this round | **Rick, 2026-10-06, tentatively**: "users there will have to install their own"; a guide at least, incorporation into our package to be looked at |
| **TB-6** | **Every artifact that carries `shekyld` carries the pinned bundle.** The Expert Bundle tarball is a pinned build input (`files:` in the gitian descriptor, tarball digest from TB-9's file), not a download in the packaging step, so the tarballs, the zip and the installer carry it as well as the `.deb` and `.rpm`, and the build stays offline and reproducible. Beside the executable in archives (the resolver's second tier); under `/opt/shekyl/<bundle_version>-<bundle_target>/` in system packages (its third); never in `/usr/local/bin`, where it would shadow a distribution's tor. Only `tor` and the libraries it loads are shipped — the pluggable transports are 30 MiB Shekyl does not use | — |
| **TB-7** | **The pin covers every file the loader opens from that directory, and the launcher lets nothing else in.** On Linux: `tor`, `libevent-2.1.so.7`, `libssl.so.3`, `libcrypto.so.3`, each with its own digest through the same canonicalize-then-hash gate. The launcher clears the environment and sets exactly one variable, the library path, to the verified binary's own directory. macOS's one library is pinned the same way; its launch environment is settled by the launch test in TB-11 | — |
| **TB-8** | **The `PATH` tier is deleted for a `Pinned` target.** A `tor` found on `PATH` has its libraries elsewhere and cannot pass a four-file pin, and `PATH` is the widest check-to-exec window the resolver has. The override, beside-the-executable and `/opt/shekyl` tiers remain | — |
| **TB-9** | **The pins are one data file.** `build.rs` reads it and emits constants: the pin stays compiled in and is never read at runtime. The file is the only source for what the packaging side needs — tarball digest, per-file digests, bundle and tor versions, target label, the `Unavailable` dispositions — and the build recipe and the packaging check read it, they do not copy it. Two gates: the packaging job hashes the files it is about to pack against the file and fails on a difference (a test edits a digest and sees the build fail), and the file's set of targets equals the set of compiled arms | — |
| **TB-10** | **Re-pin to tor 0.4.9.13** with the digests in §4, in the change that first ships the bundle. `linux-aarch64` stays on the alpha line under DQ-T0.5's existing ruling and reopen criterion | — |
| **TB-11** | **Windows and macOS become `Pinned` only with a launch test each.** Their digests are verified (§4); what is missing is evidence that the pinned binary starts under Shekyl's launcher on those platforms. Inside a macOS `.app` the tor binary falls under Shekyl's code signing and notarization | — |
| **TB-12** | **TB-2 lands last.** The refusal is merged only after every published target is `Pinned` with its bundle shipped, or `Unavailable`. Before that it would stop the GUI's bundled daemon on a platform with no pin | — |
| **TB-13** | **Licences travel with the binary.** Every artifact that carries tor carries the bundle's licence texts and the location and signature of the `tor-0.4.9.13` source. Whether a pointer to the signed upstream source meets the GPL's source obligation is to be confirmed before beta, not assumed | — |

### Refused in this round

| Name | Status | Why, and what reopens it |
| --- | --- | --- |
| `--tor-pin-override <sha256>` | **REJECTED** | It is flexibility provisioned ahead of need, and it turns a structural gate into one a unit-file edit opens. **Reopen** if a Tor security advisory cannot be answered by a Shekyl release in time |
| A signed pin manifest that moves between releases | **REJECTED** | It is an update channel: one key becomes "run this binary on every node", and a startup fetch is a beacon. A Tor CVE costs a patch release, as a CVE in any shipped dependency does. **Reopen** on the same criterion as above |
| Depending on a distribution's `tor` | **REJECTED** | A distribution build cannot match the pin; "our tor, their OpenSSL" is the same objection one layer down (finding 5) |
| Building tor from the signed source inside gitian | not this round | The route to a pinned FreeBSD and a stable `linux-aarch64`. A round of its own |

## 4. The pins proposed by TB-10 and TB-11

Downloaded 2026-10-06 from the Tor Project's archive. Each tarball carries a
Good signature from the Tor Browser Developers key
`EF6E286DDA85EA2A4BA7DE684E2C6E8793298290` (signing subkey
`022DA248432D2A0E0F54E65E316C1FACD62D07D9`), the key
`binary.rs`'s `TOR_SIGNING_KEY_FPR` names. Every bundle below ships tor
`0.4.9.13`.

| Target | Bundle | Tarball SHA-256 |
| --- | --- | --- |
| `linux-x86_64` | 15.0.24 (stable) | `8e012ec6815d7899cb64011582e2dade88e74119c6661068a2a3252de0ccd7f2` |
| `linux-aarch64` | 16.0a13 (alpha) | `e1685ff7a531e7b50b77ce231e8be397c835dd2dcb96b2fd8feb02c638acc517` |
| `windows-x86_64` | 15.0.24 (stable) | `e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65` |
| `macos-aarch64` | 15.0.24 (stable) | `d47afd04b6c751129978390ad003d74ac8b88adfbb939350f0f89999e6570644` |
| `macos-x86_64` | 15.0.24 (stable) | `8acb0b590f6be34084dcb6d84009ac0c61cc7c5261b7a19d2ab94845aa9bd5b6` |

Extracted files, by target:

| Target | File | SHA-256 |
| --- | --- | --- |
| `linux-x86_64` | `tor` | `74f5a47bfe0fc7f7c3ec2fe6c772ec6e52d4a9e9e9c95c7f274f5330e02a8813` |
| | `libevent-2.1.so.7` | `b51ca562ec232785856c454ce4f3621d957f39d0db87919e237590b0331544ff` |
| | `libssl.so.3` | `e95f55c73b63a4e25db7b9c74abdd35c42829ca1dc68f2fb17ae71c4d841381c` |
| | `libcrypto.so.3` | `6ed9fc77689324da28567478e0ed226f4f450f71b47852088e9b0b9220eb0404` |
| `linux-aarch64` | `tor` | `5ad180229237d10e670ae0475b21d788272da0c13bb89c2617223afcfe3ff477` |
| | `libevent-2.1.so.7` | `097958f586ffce01273a57557e17062357d92343724e1f112ea61ad8261ce577` |
| | `libssl.so.3` | `080e70629ffe87e3c5bbbb59bc231da4c5d68100dd6b43b522bcaf8447d85eaf` |
| | `libcrypto.so.3` | `f50977cdfd82a28ab7ac327daa11841486193888365a149f1409ce5a3b1e61b3` |
| `windows-x86_64` | `tor.exe` | `90bbdcafd586feea608a5e9b7d3959f4ee194f7770755cfde8fab240e9773ad1` |
| `macos-aarch64` | `tor` | `85843ba0bfc876411d2b237f923a8e6a230870c60c1af23fd68206df8abc2ad7` |
| | `libevent-2.1.7.dylib` | `6dde3faf59255b7cf0cc20d0b3cdf78622266fbf13c534300b8884c76d89b739` |
| `macos-x86_64` | `tor` | `936be37bed7175f1c011543f318e996a9bfe624b8d0ac9968c4304e2751cb2f3` |
| | `libevent-2.1.7.dylib` | `38aea0316e01e1fc52a15941bf523c8bc018ca90655cfa90de568b4a86a82b4b` |

These are a proposal's evidence, not the pin of record. The pin of record is
whatever `binary.rs` compiles, recorded through `RELEASE_CHECKLIST.md`'s
"Bundled Tor pin current" procedure when TB-10 lands.

## 5. Order of work, if the rows are ruled

1. **Linux, both architectures, every artifact type:** TB-6 to TB-10 and TB-13,
   with TB-4's type. Validated by the crate's tests, the `tor-pin-verify`
   workflow at the new bundle version, and a gitian dry run.
2. **Windows and macOS:** TB-11, a pin and a launch test for each.
3. **FreeBSD:** TB-5's `Unavailable` arm and its user guide.
4. **The refusal:** TB-2, under TB-12.

The Foundation's own hosts are reconfigured one at a time after step 1, to the
canonical location, watching the network recover from each dropped node.

## 6. What breaks first if this is wrong

- **TB-7's environment clearing** removes variables tor itself may read. The
  managed launch passes everything as arguments today (data directory, control
  port, SOCKS port, log), so nothing is expected to be lost; the crate's live
  lifecycle tests are where a dependence on the environment would show.
- **TB-2** turns an install mistake into a daemon that does not start. That is
  the intent, and TB-12 is what keeps it from reaching a platform that cannot
  satisfy it.
- **TB-8** removes a path a developer may be using. A developer's own tor is
  the override tier's job, and it stays.
