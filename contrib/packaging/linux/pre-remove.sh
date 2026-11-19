#!/bin/sh
# Run by the .deb and the .rpm before they are removed (fpm --before-remove;
# fpm runs it on removal only, not when an upgrade replaces the package).
# Every instance of the daemon, shekyld@<network>, is stopped and disabled
# before its files go: the running ones, and the enabled ones that are not
# running. The account, /etc/shekyl and the chain data are kept
# (INPUT_GRAMMAR.md IG-Q64, Purge).
set -e

if [ -d /run/systemd/system ]; then
    units="$(
        {
            systemctl list-units --all --plain --no-legend 'shekyld@*.service' | awk '{ print $1 }'
            for link in /etc/systemd/system/*.wants/shekyld@*.service; do
                if [ -L "$link" ]; then basename "$link"; fi
            done
        } | sort -u
    )"
    for unit in $units; do
        systemctl disable --now "$unit"
    done
fi
