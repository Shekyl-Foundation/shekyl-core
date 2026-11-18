#!/bin/sh
# Run by the .deb and the .rpm after install and after upgrade (fpm
# --after-install / --after-upgrade), once pre-install.sh has refused any
# shekyl account that is a login.
#
# It applies what the package declares: the account (shekyl.sysusers) and
# /etc/shekyl (shekyl.tmpfiles), then reloads systemd so the units it ships
# (shekyld.service, shekyl.slice and the tunnel's) are known. It neither
# enables, starts nor restarts the daemon: the operator runs
# `systemctl enable --now shekyld` after putting any settings in
# /etc/shekyl/shekyld-<network>.toml, and `systemctl restart shekyld` after
# an upgrade.
set -e

systemd-sysusers shekyl.conf
systemd-tmpfiles --create shekyl.conf

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
