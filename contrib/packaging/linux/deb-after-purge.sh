#!/bin/sh
# Run by the .deb's postrm when it is purged (dpkg's `purge`), after its files
# are gone (INPUT_GRAMMAR.md IG-Q64, Purge). It removes the settings files
# the package places, one per public network, and then /etc/shekyl only if
# nothing else is in it: an operator's own files there survive, and the
# directory stays with them. /etc/shekyl-tunnel, the tunnel's, holds only
# the operator's files, so it goes only when it is empty. The chain data
# and logs, which systemd created for the service, are the operator's to
# delete, and the system accounts are kept so a reused uid never owns
# another account's files. The .rpm has no purge; its erase keeps these
# files.
set -e

for network in mainnet testnet stagenet; do
    rm -f "/etc/shekyl/shekyld-$network.toml"
done
rmdir /etc/shekyl 2>/dev/null || :
rmdir /etc/shekyl-tunnel 2>/dev/null || :
