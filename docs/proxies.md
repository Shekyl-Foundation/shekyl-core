# Proxy usage in the Shekyl ecosystem
The CLI/RPC wallets and the daemon both support proxies, each with its own
options.

## Wallet
`shekyl-cli` and `shekyl-wallet-rpc` take a proxy with `--daemon-socks`, an IP
address and a port. It is SOCKS5, and the proxy resolves names, so the wallet
sends no DNS query of its own. The option can only be given once:

```
--daemon-socks 127.0.0.1:9050
--daemon-socks [::1]:1050
```

The value holds no user name or password, and SOCKS 4 is not offered. A proxy
that needs a login is not reachable from the wallet. An onion
`--daemon-endpoint` requires this option.

## Daemon

The daemon does not take a proxy option. It has two connectors, each a row
of its configuration (`shekyld --help`; `docs/EXECUTABLES.md`):

- **Tor** (`tor`): `managed` runs the bundled Tor (the default; `tor-file`
  names the binary); `operator` uses a Tor you run, named by `tor-socks`,
  with `tor-onion` and `tor-onion-listen` for the onion service that makes
  the node reachable, and `tor-socks-username` and `tor-socks-password`
  when that Tor's SOCKS port asks for them; `off` is clearnet only. Transactions this node
  originates leave over Tor when the connector is on.
- **Clearnet** (`clearnet`): `on` (the default) or `off`. `clearnet-socks`
  names a SOCKS proxy for clearnet dials, with `clearnet-socks-username`
  and `clearnet-socks-password` in the configuration file only; a proxy
  cannot forward inbound connections, so `clearnet-listen none` is the
  matching posture when every dial leaves through one.
- **SOCKS username and password.** A pair is given whole, in the
  configuration file only, and is sent to that proxy and no other. A file
  that holds one may be read by root and the daemon's account, and by the
  daemon's group only while that account is the group's only member: a
  service install keeps it `root:<daemon group>` `0640` under `/etc/shekyl`
  `root:shekyl` `0750`, a per-account install `0600`. An access-control list
  that names anyone else refuses, and so does a group that holds anyone
  else, by its member list or as an account's primary group. The check
  reads the accounts the system enumerates. A directory service that is
  stopped, or that does not list its accounts, is treated as listing none
  of them, so its accounts are not seen: keep the daemon's group a local
  group. A proxy that refuses
  the pair fails each dial through it, and the log names the two options to
  fix once a minute; the daemon keeps running.

```bash
# The operator's own Tor, reachable as an onion service
shekyld --tor operator --tor-socks 127.0.0.1:9050 \
    --tor-onion <your-onion>.onion:11021 --tor-onion-listen 127.0.0.1:11021

# Clearnet dials through a SOCKS proxy, no inbound
shekyld --clearnet-socks 192.168.0.10:1050 --clearnet-listen none
```

Hidden-service peers given by `p2p-peer` or `p2p-closed-peer` are dialled
through the Tor connector; there are built-in seed nodes for each network.
