# Proxy usage in the Shekyl ecosystem
The CLI/RPC wallets and daemon both support proxies and use the same parameters
to configure them. Currently socks 4, 4a, and 5 are supported and can be
selected with command-line options.

## Wallet
The CLI and RPC wallets support proxies via the `--proxy` option. The format
for usage is `[socks5://[user:pass]]host:port`. The square brackets indicate
an optional portion. This option can only be specified once. Examples:

```
--proxy 192.168.0.10:1050
--proxy socks5://192.168.0.10:1050
--proxy socks5://username:password@192.168.0.10:1050
--proxy [::1]:1050
--proxy socks5://[::1]:1050
--proxy socks5://username:password@[::1]:1050
```

The first connects to `192.168.0.10` on port `1050` using socks 4a. The second
connects to the same location using socks 5. The third uses socks 5 at the same
location and sends user authentication if prompted by the proxy server. The
last three are identical to the first 3, except an IPv6 address is used
instead. While IPv6 connections are invalid for Socks 4 and 4a, the proxy
server itself can be connected using IPv6.

The username and password fields both support "percent-encoding" for special
character support. As an example, `%40` gets converted to `@`, such that
`username:p%40ssword` gets converted to `username:p@ssword`. This allows that
specific character to be used; specifying the character directly will
incorrectly change the specification of the hostname.

> NOTE: The username+password will show up in the process list and can be read
> by other programs. It is recommended that `--config-file` be used to store
> username+password options. The format for a config file is `option=value`,
> so in this example the file would contain:
> `proxy=socks5://username:password@192.168.0.10:1080`.

The CLI and RPC wallets currently reject hosts that do **NOT** end in `.onion`
**unless** `--daemon-ssl-ca-certificates`,
`--daemon-ssl-allow-any-cert`, or `--daemon-ssl-allowed-fingerprints` is used.
If an onion address is used, the hostname contains the certificate
verification, providing decent security against man-in-the-middle (MitM)
attacks. The two `--daemon-ssl-*` options support specifying exact
certificates, also preventing MitM attacks.

> Perhaps the wallets should be relaxed to allow system-CA checks, but for now
> certificates must be strictly provided.

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
  configuration file only (readable by the daemon's account and root
  alone), and is sent to that proxy and no other. A proxy that refuses it
  fails each dial through it, and the log names the two options to fix
  once a minute; the daemon keeps running.

```bash
# The operator's own Tor, reachable as an onion service
shekyld --tor operator --tor-socks 127.0.0.1:9050 \
    --tor-onion <your-onion>.onion:11021 --tor-onion-listen 127.0.0.1:11021

# Clearnet dials through a SOCKS proxy, no inbound
shekyld --clearnet-socks 192.168.0.10:1050 --clearnet-listen none
```

Hidden-service peers given by `p2p-peer` or `p2p-closed-peer` are dialled
through the Tor connector; there are built-in seed nodes for each network.
