#!/bin/sh
# Run by the .deb after install and after upgrade (fpm --after-install /
# --after-upgrade). fpm places this script's body ahead of its own systemd
# hook, which reloads systemd on install and, on upgrade, restarts
# shekyld.service only when it is already enabled. The hook never enables
# or starts the daemon: the operator does, with
# `systemctl enable --now shekyld`, once /etc/shekyl holds the node's file.
set -e

# The service's account. shekyld.service runs as User=shekyl and
# Group=shekyl, and systemd refuses to start a unit whose account does not
# exist (status 217/USER). A system account with no home and no login
# shell, made once and kept across upgrades and removal, as FreeBSD's rc.d
# script names its own (contrib/packaging/freebsd/shekyld). useradd is in
# Debian's essential `passwd` package. A group already named shekyl is
# joined rather than refused.
if ! getent passwd shekyl >/dev/null 2>&1; then
    if getent group shekyl >/dev/null 2>&1; then
        useradd --system --gid shekyl --home-dir /nonexistent --no-create-home \
            --shell /usr/sbin/nologin --comment "Shekyl daemon" shekyl
    else
        useradd --system --user-group --home-dir /nonexistent --no-create-home \
            --shell /usr/sbin/nologin --comment "Shekyl daemon" shekyl
    fi
fi

# The package ships a slice unit beside the service, and a unit file systemd
# has not been told about is not a slice a service can join.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
